/* grapheneX web interface controller */

$(document).ready(initializePage);

var socket;
var currentNamespace = "";

function announce(message) {
    // Screen readers read this out; it is visually hidden.
    $("#live-region").text(message);
}

function Module(module, socket) {
    this.data = module;
    this.name = module.name;
    this.iconBase = String(this.name).replace(/[^A-Za-z0-9_-]/g, "_");
    this.socket = socket;
    this.lastRunId = "";

    this.writeLog = (message) => {
        var currentTime = new Date().toLocaleTimeString();
        var $logs = $("#" + this.iconBase + "_logs");
        $logs.val($logs.val() + currentTime + " > " + message + "\n");
        $logs.scrollTop($logs[0].scrollHeight);
    };

    this.setBusy = (busy) => {
        $("#" + this.iconBase + "_execute_btn").prop("disabled", busy);
        $("#" + this.iconBase + "_check_btn").prop("disabled", busy);
    };

    this.openDrawer = (open) => {
        var $drawer = $("#" + this.iconBase + "_drawer");
        var $button = $("#" + this.iconBase + "_btn");
        if (open) {
            $drawer.prop("hidden", false).stop(true, true).slideDown(200);
        } else {
            $drawer.stop(true, true).slideUp(200, () => $drawer.prop("hidden", true));
        }
        $button.attr("aria-expanded", open ? "true" : "false");
        $("#" + this.iconBase + "_ico").toggleClass("rotated", open);
    };

    this.render = () => {
        $("#modules").append(getModuleBox(this.data));

        var $button = $("#" + this.iconBase + "_btn");
        var $execute = $("#" + this.iconBase + "_execute_btn");
        var $check = $("#" + this.iconBase + "_check_btn");
        var $revert = $("#" + this.iconBase + "_revert_btn");
        var $logs = $("#" + this.iconBase + "_logs");

        $logs.val("# " + (this.data.desc || "") + "\n# apply : " + (this.data.source || "") +
            "\n# audit : " + (this.data.check || "") +
            "\n# revert: " + (this.data.revert || this.data.revert_strategy || "") + "\n");

        $button.on("click", () => {
            var expanded = $button.attr("aria-expanded") === "true";
            this.openDrawer(!expanded);
        });

        $execute.on("click", () => {
            $execute.find("i").addClass("rotate_cogs");
            this.setBusy(true);
            this.socket.emit("harden", this.name);
            announce("Applying " + this.name);
        });

        $check.on("click", () => {
            this.socket.emit("check_module", this.name);
            announce("Auditing " + this.name);
        });

        $revert.on("click", () => {
            this.socket.emit("revert_run", { run_id: this.lastRunId || "last" });
            announce("Reverting the last change for " + this.name);
        });

        this.socket.on(this.name + "_log", (data) => {
            if (data.msg) {
                this.writeLog(data.msg);
                announce(data.msg.substring(0, 200));
            }
            if (data.run_id) {
                this.lastRunId = data.run_id;
            }
            if (data.state === "success" || data.state === "compliant") {
                this.setBusy(false);
                $execute.find("i").removeClass("rotate_cogs fa-cog").addClass("fa-check");
            } else if (data.state === "error" || data.state === "drift") {
                this.setBusy(false);
                $execute.find("i").removeClass("rotate_cogs").addClass("fa-times-circle");
            }
        });
    };
}

function renderModules(modules) {
    $("#modules").empty();
    modules.forEach((module) => new Module(module, socket).render());
    $(".overlay").fadeOut("slow");
}

/* Search module event */
function bindSearch() {
    $("#module_search").off("keyup").on("keyup", function () {
        var query = $(this).val();
        setTimeout(() => {
            socket.emit("search_module", { query: query });
        }, 300);
    });
    $("#module_search").closest("form").off("submit").on("submit", (event) => event.preventDefault());
}

/* History panel */
function renderHistory(data) {
    var $list = $("#history-list").empty();
    var pending = data.pending || [];
    if (!data.records || data.records.length === 0) {
        $("<li>", { class: "text-muted" }).text("Nothing applied yet.").appendTo($list);
    }
    data.records.forEach((record) => {
        var state = record.reverted ? "reverted" : (record.ok ? "applied" : "failed");
        if (record.action === "audit") {
            state = record.ok ? "audit: compliant" : "audit: drift";
        } else if (record.action === "revert") {
            state = record.ok ? "revert ok" : "revert failed";
        }
        var $item = $("<li>").appendTo($list);
        $("<strong>").text(record.module).appendTo($item);
        $("<span>", { class: "text-muted" }).text(" \u00b7 " + state + " \u00b7 " + record.run_id).appendTo($item);
        if (record.action === "apply" && record.ok && pending.indexOf(record.run_id) !== -1) {
            $("<button>", { type: "button", class: "btn btn-sm ml-2" })
                .text("Revert")
                .attr("aria-label", "Revert " + record.module + " run " + record.run_id)
                .on("click", () => socket.emit("revert_run", { run_id: record.run_id }))
                .appendTo($item);
        }
    });
    $("#history-integrity").text(
        data.chain_ok
            ? "Journal integrity verified (hash chain)."
            : "WARNING: journal integrity check failed: " + (data.problems || []).join("; ")
    );
    $("#revert-last").prop("disabled", pending.length === 0);
}

function refreshHistory() {
    socket.emit("get_history", { limit: 20 });
}

/* New module save event */
function saveModal() {
    var files = ($("#amod_files").val() || "").split(",").map((item) => item.trim()).filter(Boolean);
    socket.emit("add_module", {
        ns: $("#amod_ns_list").find(".active").text().trim(),
        name: $("#amod_name").val(),
        desc: $("#amod_desc").val(),
        cmd: $("#amod_cmd").val(),
        check: $("#amod_check").val(),
        revert: $("#amod_revert").val(),
        files: files,
        risk: $("#amod_risk").val(),
        shell: $("#amod_shell").prop("checked"),
        su: $("#amod_su").prop("checked"),
        rr: $("#amod_rr").prop("checked")
    });
}

/* Prepare the new module modal */
function prepareModal() {
    $("#addModuleModal").on("show.bs.modal", function () {
        $("#openModal").find(".fa-plus").addClass("rotate_cogs");
        var $addNsElem = $("#amod_ns_list > li").last();
        var $input = $("<input>", {
            class: "form-control",
            id: "amod_new_ns",
            style: "padding: .75rem 1.25rem; height: auto;",
            placeholder: "Namespace name...",
            type: "text"
        });
        $addNsElem.off("click").on("click", () => {
            if ($("#amod_new_ns").length === 0)
                $addNsElem.before($input);
            $addNsElem.hide();
            $input.val("").focus();
            $input.off("keypress").on("keypress", function (event) {
                if (event.keyCode === 13) {
                    var newNsText = $input.val();
                    var $newNsElem = $("<li>", { class: "list-group-item", id: "new_ns_" + newNsText })
                        .text(newNsText);
                    $input.replaceWith($newNsElem);
                    $newNsElem.addClass("active");
                    $addNsElem.removeClass("active").show();
                    event.preventDefault();
                }
            });
        });
    });
    $("#addModuleModal").on("hidden.bs.modal", function () {
        $("#openModal").find(".fa-plus").removeClass("rotate_cogs");
    });
    $("#amod_save").on("click", saveModal);
}

/* Show message with modal */
function createMessage(data) {
    var messageClass = "text-white bg-" + String(data.tag || "primary").replace(/[^a-z]/g, "");
    var $modal = $("#messageModal");
    $modal.modal({ backdrop: false });
    $modal.find(".modal-content").addClass(messageClass).text(data.content || "");
    var seconds = typeof data.duration === "undefined" ? 1000 : data.duration;
    setTimeout(() => {
        $modal.modal("hide");
        $modal.find(".modal-content").removeClass(messageClass);
    }, seconds);
}

/* Initialize the page and connect */
function initializePage() {
    if (window.AOS) {
        AOS.init({ disable: window.matchMedia("(prefers-reduced-motion: reduce)").matches });
    }

    $("#systemdiv").on("show.bs.collapse", function () {
        $(".opensystembtn i").addClass("rotate_arrow");
    });
    $("#systemdiv").on("hide.bs.collapse", function () {
        $(".opensystembtn i").removeClass("rotate_arrow");
    });

    prepareModal();
    socket = io.connect(location.protocol + "//" + document.domain + ":" + location.port);

    socket.on("log_message", createMessage);
    socket.on("get_history", renderHistory);
    socket.on("run_recorded", refreshHistory);
    socket.on("revert_result", (result) => {
        if (result && result.ok) {
            announce("Revert completed for " + result.module);
        }
        refreshHistory();
    });
    socket.on("auth", (data) => {
        createMessage({ tag: "warning", content: (data && data.text) || "Not authenticated" });
    });

    $("#history-refresh").on("click", refreshHistory);
    $("#revert-last").on("click", () => socket.emit("revert_run", { run_id: "last" }));

    socket.emit("get_namespaces", {});
    socket.on("get_namespaces", (data) => {
        var namespaces = (data && data.namespaces) || [];
        $("#namespaces").empty();
        namespaces.forEach((namespace) => {
            $("<li>").append($("<button>", { type: "button", class: "dropdown-item" }).text(namespace))
                .appendTo($("#namespaces"));
            if ($("#ns_list_" + namespace).length === 0) {
                $("#amod_ns_list").prepend(
                    $("<li>", { class: "list-group-item", id: "ns_list_" + namespace }).text(namespace)
                );
            }
        });
        socket.emit("get_current_namespace", {});
        $("#namespaces").off("click").on("click", "button", function (event) {
            event.preventDefault();
            var namespace = $(this).text();
            $("#current_namespace").text(namespace);
            socket.emit("send_current_namespace", namespace);
        });
    });

    socket.on("get_current_namespace", (data) => {
        currentNamespace = data.current_namespace;
        $("#current_namespace").text(currentNamespace);
        socket.emit("send_current_namespace", currentNamespace);
    });

    socket.on("get_module", (data) => {
        renderModules(data || []);
        bindSearch();
        refreshHistory();
    });

    socket.on("search_module", (data) => {
        renderModules((data && data.result) || []);
    });

    socket.on("new_module_added", (count) => {
        $("#addModuleModal").modal("toggle");
        $("#addModuleModal").find("input,textarea,select").val("");
        $("[id^='new_ns_']").remove();
        $("#modulecount").text(count);
        socket.emit("get_namespaces", {});
    });
}
