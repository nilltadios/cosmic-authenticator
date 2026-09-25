// SPDX-License-Identifier: GPL-3.0-only

//! Proton sign-in window, as the official app opens one (its `src-tauri/src/auth.rs`):
//! a 400x600 web view on Proton's account site. Proton's page handles the
//! password, 2FA and CAPTCHA. When the site redirects to a page whose path
//! contains `/login`, that navigation is blocked and its URL fragment, which
//! holds the fork selector and key, is printed on stdout.
//!
//!   cosmic-authenticator-login URL TITLE USER_AGENT
//!
//! Exit status 0 with the fragment on stdout; 1 if the window was closed first.

use std::cell::Cell;
use std::io::Write;
use std::rc::Rc;

use webkit6::prelude::*;
use webkit6::{NavigationPolicyDecision, NetworkSession, PolicyDecisionType, WebView, gio, glib, gtk};

/// The fragment of a Proton login callback, or `None` for any other address.
/// The official app checks only for `/login` in the path; requiring a selector
/// too keeps a plain visit to the login page from ending the flow.
fn callback_fragment(uri: &str) -> Option<String> {
    let parsed = glib::Uri::parse(uri, glib::UriFlags::NONE).ok()?;
    let fragment = parsed.fragment()?.to_string();
    let has_selector = fragment.split('&').any(|pair| pair.starts_with("selector="));
    (parsed.path().contains("/login") && has_selector).then_some(fragment)
}

fn main() -> glib::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let [_, url, title, user_agent] = args.as_slice() else {
        eprintln!("usage: cosmic-authenticator-login URL TITLE USER_AGENT");
        return glib::ExitCode::FAILURE;
    };
    let (url, title, user_agent) = (url.clone(), title.clone(), user_agent.clone());

    let app = gtk::Application::builder()
        .application_id("dev.nilltadios.CosmicAuthenticator.Login")
        .flags(gio::ApplicationFlags::NON_UNIQUE)
        .build();
    let signed_in = Rc::new(Cell::new(false));

    let signed_in_activate = signed_in.clone();
    app.connect_activate(move |app| {
        // Nothing from the sign-in page is kept on disk once the window closes.
        let view = WebView::builder().network_session(&NetworkSession::new_ephemeral()).build();
        if let Some(settings) = webkit6::prelude::WebViewExt::settings(&view) {
            settings.set_user_agent(Some(&user_agent));
        }

        let window = gtk::ApplicationWindow::builder()
            .application(app)
            .title(title.as_str())
            .default_width(400)
            .default_height(600)
            .child(&view)
            .build();

        let signed_in = signed_in_activate.clone();
        let app = app.clone();
        view.connect_decide_policy(move |_, decision, kind| {
            if kind != PolicyDecisionType::NavigationAction {
                return false;
            }
            let Some(uri) = decision
                .downcast_ref::<NavigationPolicyDecision>()
                .and_then(|navigation| navigation.navigation_action())
                .and_then(|mut action| action.request())
                .and_then(|request| request.uri())
            else {
                return false;
            };
            let Some(fragment) = callback_fragment(&uri) else {
                return false;
            };
            decision.ignore();
            let mut stdout = std::io::stdout();
            if writeln!(stdout, "{fragment}").and_then(|()| stdout.flush()).is_ok() {
                signed_in.set(true);
            }
            app.quit();
            true
        });

        view.load_uri(&url);
        window.present();
    });

    app.run_with_args(&[] as &[&str]);
    if signed_in.get() { glib::ExitCode::SUCCESS } else { glib::ExitCode::FAILURE }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_the_fragment_of_a_login_callback_only() {
        let callback = "https://authenticator.proton.me/login#selector=abc&state=xyz&sk=key&pv=3";
        assert_eq!(callback_fragment(callback).as_deref(), Some("selector=abc&state=xyz&sk=key&pv=3"));
        assert_eq!(callback_fragment("https://account.proton.me/login"), None);
        assert_eq!(callback_fragment("https://account.proton.me/authorize?app=x#selector=abc"), None);
    }
}
