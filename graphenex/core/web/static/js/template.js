/*
    Safe DOM builders for module cards.

    Everything that comes from modules.json is inserted with .text(), never by
    string concatenation, so a crafted description or module name cannot break
    out of the markup (DOM XSS).
*/

function moduleElementId(name, suffix) {
    // Module names are validated as [A-Za-z0-9_], but be defensive anyway.
    var safe = String(name).replace(/[^A-Za-z0-9_-]/g, "_");
    return safe + (suffix || "");
}

function getModuleBox(module) {
    var name = module.name;
    var risk = module.risk || "medium";
    var idBase = moduleElementId(name);

    var $box = $("<div>", { class: "module-box deep", id: idBase + "_div" });
    var $row = $("<div>", { class: "row" }).appendTo($box);
    var $header = $("<div>", { class: "col-9 d-flex justify-content-between" }).appendTo($row);
    var $toggle = $("<button>", {
        type: "button",
        class: "module-toggle",
        id: idBase + "_btn",
        "aria-expanded": "false",
        "aria-controls": idBase + "_drawer"
    }).appendTo($header);

    var $text = $("<div>", { class: "mr-auto p-2" }).appendTo($toggle);
    var $title = $("<h6>", { class: "module-title", style: "word-break: break-all; margin-bottom: 0.25rem;" })
        .text(name)
        .appendTo($text);
    $("<span>", { class: "badge-risk" }).text(risk).appendTo($title);
    if (module.requires_restart) {
        $("<span>", { class: "badge-risk" }).text("restart").appendTo($title);
    }
    $("<p>", { class: "text-muted", style: "font-size: 13px; margin-bottom:0" })
        .text(module.desc || "")
        .appendTo($text);

    var $iconWrap = $("<div>", { class: "col-3 text-right mt-1" }).appendTo($row);
    $("<span>", { "aria-hidden": "true" })
        .append($("<i>", { style: "font-size: 52px", id: idBase + "_ico", class: "fas fa-arrow-circle-right" }))
        .appendTo($iconWrap);

    var $drawerWrap = $("<div>", { class: "container-fluid mt-1" }).appendTo($row);
    var $drawer = $("<div>", {
        class: "drawer-content",
        id: idBase + "_drawer",
        hidden: "hidden"
    }).appendTo($drawerWrap);

    $("<label>", { class: "visually-hidden", for: idBase + "_logs" })
        .text("Output for " + name)
        .appendTo($drawer);
    $("<textarea>", {
        class: "logs consolas font-small text-muted",
        name: "logs",
        id: idBase + "_logs",
        cols: "30",
        rows: "5",
        readonly: "readonly",
        spellcheck: "false"
    }).appendTo($drawer);

    var $actions = $("<div>", { class: "btn-group d-flex", role: "group", "aria-label": "Actions for " + name })
        .appendTo($drawer);
    $("<button>", { type: "button", class: "btn btn-block", id: idBase + "_execute_btn" })
        .append("Run ")
        .append($("<i>", { class: "fas fa-cog", "aria-hidden": "true" }))
        .appendTo($actions);
    $("<button>", { type: "button", class: "btn btn-block", id: idBase + "_check_btn" })
        .append("Check ")
        .append($("<i>", { class: "fas fa-clipboard-check", "aria-hidden": "true" }))
        .appendTo($actions);
    $("<button>", { type: "button", class: "btn btn-block", id: idBase + "_revert_btn" })
        .append("Revert ")
        .append($("<i>", { class: "fas fa-undo", "aria-hidden": "true" }))
        .attr("title", module.revertible ? "Revert this module's last applied run" : "This module cannot be reverted")
        .prop("disabled", !module.revertible)
        .appendTo($actions);

    return $box;
}
