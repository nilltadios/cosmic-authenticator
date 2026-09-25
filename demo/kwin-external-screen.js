// KWin script used by demo/on-screen.sh. Moves this app's windows (including
// the sign-in window) to one screen, centred, and gives focus back to the
// window that had it, so testing does not interrupt typing on another screen.
// on-screen.sh fills in the target screen and whether to go full screen.
const TARGET = "__TARGET__";
const FULLSCREEN = __FULLSCREEN__;
const PREFIX = "dev.nilltadios.cosmicauthenticator";

const ours = (w) => w && String(w.resourceClass).toLowerCase().startsWith(PREFIX);
let lastOther = ours(workspace.activeWindow) ? null : workspace.activeWindow;
const justAdded = new Set();

workspace.windowActivated.connect((w) => {
    if (!w) return;
    if (!ours(w)) {
        lastOther = w;
    } else if (justAdded.has(w.internalId.toString())) {
        justAdded.delete(w.internalId.toString());
        if (lastOther) workspace.activeWindow = lastOther;
    }
});

workspace.windowAdded.connect((w) => {
    if (!ours(w)) return;
    const output = workspace.screens.find((s) => s.name === TARGET);
    if (!output) return;
    justAdded.add(w.internalId.toString());
    workspace.sendClientToScreen(w, output);
    const area = output.geometry;
    const frame = w.frameGeometry;
    const width = Math.min(frame.width, area.width);
    const height = Math.min(frame.height, area.height);
    w.frameGeometry = {
        x: area.x + Math.round((area.width - width) / 2),
        y: area.y + Math.round((area.height - height) / 2),
        width,
        height,
    };
    if (FULLSCREEN) w.fullScreen = true;
    // Giving focus back would leave the new window under whatever is on that
    // screen, so raise it without activating it.
    workspace.raiseWindow(w);
    if (lastOther) workspace.activeWindow = lastOther;
});
