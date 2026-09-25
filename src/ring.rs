//! Countdown ring drawn on a canvas. It changes once a second, when the app
//! ticks, so the canvas never asks for frames of its own.

use std::f32::consts::{FRAC_PI_2, TAU};

use cosmic::iced::{Color, Point, Radians, Rectangle, mouse};
use cosmic::widget::canvas::{self, Frame, Geometry, Path, Stroke, Text, path::Arc};
use cosmic::{Renderer, Theme};

pub struct Countdown {
    pub remaining: u64,
    pub period: u64,
}

impl<Message> canvas::Program<Message, Theme, Renderer> for Countdown {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &Renderer,
        theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<Geometry<Renderer>> {
        let cosmic = theme.cosmic();
        let text: Color = cosmic.on_bg_color().into();
        // Proton's thresholds: the ring warns at 10 seconds and alarms at 5.
        let arc_color: Color = match self.remaining {
            0..=5 => cosmic.destructive_color(),
            6..=10 => cosmic.warning_color(),
            _ => cosmic.accent_color(),
        }
        .into();

        let mut frame = Frame::new(renderer, bounds.size());
        let center = frame.center();
        let width = 2.5;
        let radius = frame.width().min(frame.height()) / 2.0 - width;

        // tiny-skia repaints only the damaged area, and takes a stroke's damage
        // from its path without the stroke width. The outer half of the ring
        // would then keep pixels from earlier seconds, such as a red sliver
        // where the arc used to end. An invisible fill over the whole canvas
        // makes every redraw cover the full ring.
        frame.fill_rectangle(Point::ORIGIN, frame.size(), Color::TRANSPARENT);

        frame.stroke(
            &Path::circle(center, radius),
            Stroke::default()
                .with_width(width)
                .with_color(Color { a: 0.15, ..text }),
        );

        let fraction = self.remaining as f32 / self.period.max(1) as f32;
        if fraction > 0.0 {
            let start = -FRAC_PI_2;
            let arc = Path::new(|builder| {
                builder.arc(Arc {
                    center,
                    radius,
                    start_angle: Radians(start),
                    end_angle: Radians(start + TAU * fraction),
                });
            });
            frame.stroke(&arc, Stroke::default().with_width(width).with_color(arc_color));
        }

        frame.fill_text(Text {
            content: self.remaining.to_string(),
            position: Point::new(center.x, center.y),
            color: text,
            size: 11.0.into(),
            align_x: cosmic::iced::advanced::text::Alignment::Center,
            align_y: cosmic::iced::alignment::Vertical::Center,
            ..Text::default()
        });

        vec![frame.into_geometry()]
    }
}
