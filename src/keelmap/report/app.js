(function () {
  "use strict";
  // Every string in DATA may come from network traffic. It is only ever
  // placed with textContent or as Cytoscape canvas labels, never as markup.
  var DATA = JSON.parse(document.getElementById("keelmap-data").textContent);
  var panel = document.getElementById("panel");
  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var nodeById = {};
  DATA.nodes.forEach(function (n) { nodeById[n.id] = n; });
  DATA.groups.forEach(function (g) { nodeById[g.id] = g; });
  var kindLabel = {};
  DATA.kinds.forEach(function (k) { kindLabel[k.kind] = k.label; });
  kindLabel.group = "IEC 61162-450 multicast group";

  // ---------- small helpers ----------
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function add(parent) {
    for (var i = 1; i < arguments.length; i++) if (arguments[i]) parent.appendChild(arguments[i]);
    return parent;
  }
  function child(parent, node) { parent.appendChild(node); return node; }
  var nf = new Intl.NumberFormat("en-GB");
  function num(n) { return nf.format(n); }
  var df = new Intl.DateTimeFormat("en-GB", {
    day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit",
    timeZone: "UTC"
  });
  function when(iso) { return iso ? df.format(new Date(iso)) + " UTC" : "unknown"; }
  function span(a, b) {
    if (!a) return "Time unknown";
    return a === b ? "Seen once, " + when(a) : "Seen " + when(a) + " to " + when(b);
  }
  function plural(n, one, many) { return num(n) + " " + (n === 1 ? one : many); }
  function frameText(frames) {
    if (!frames || !frames.length) return "No frame cited";
    if (frames.length === 1) return "Frame " + frames[0];
    if (frames.length === 2) return "Frames " + frames[0] + " and " + frames[1];
    return "Frames " + frames.slice(0, -1).join(", ") + " and " + frames[frames.length - 1];
  }
  function css(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

  var SVG = "http://www.w3.org/2000/svg";
  function svg(cls, w, h, build) {
    var s = document.createElementNS(SVG, "svg");
    s.setAttribute("class", cls); s.setAttribute("viewBox", "0 0 " + w + " " + h); s.setAttribute("aria-hidden", "true");
    build(s);
    return s;
  }
  function shape(s, tag, attrs) {
    var e = document.createElementNS(SVG, tag);
    Object.keys(attrs).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    s.appendChild(e);
  }
  function symbol(kind) {
    return svg("sym", 22, 22, function (s) {
      switch (kind) {
        case "gateway": shape(s, "polygon", { points: "11,1 21,11 11,21 1,11", "class": "f-buff" }); break;
        case "server": shape(s, "rect", { x: 2, y: 4, width: 18, height: 14, rx: 3, "class": "f-buff" }); break;
        case "ais": shape(s, "polygon", { points: "1,3 11,21 21,3 11,9", "class": "f-green" }); break;
        case "navigation": shape(s, "polygon", { points: "11,2 21,20 1,20", "class": "f-green" }); break;
        case "client": shape(s, "circle", { cx: 11, cy: 11, r: 9, "class": "f-plain" }); break;
        case "infrastructure": shape(s, "polygon", { points: "6,2 16,2 21,11 16,20 6,20 1,11", "class": "f-plain" }); break;
        case "network": shape(s, "rect", { x: 3, y: 3, width: 16, height: 16, "class": "f-plain" }); break;
        case "group": shape(s, "rect", { x: 1, y: 5, width: 20, height: 12, rx: 6, "class": "f-faint", "stroke-dasharray": "3 2" }); break;
        default: shape(s, "circle", { cx: 11, cy: 11, r: 6, "class": "f-faint" });
      }
    });
  }
  function lineKey(cls) {
    return svg("line", 34, 10, function (s) { shape(s, "line", { x1: 1, y1: 5, x2: 33, y2: 5, "class": cls }); });
  }

  // ---------- evidence ----------
  function evidenceList(item, summaryText) {
    if (!item.evidence || !item.evidence.length) return null;
    var d = el("details");
    add(d, el("summary", null, summaryText || plural(item.count, "record", "records")));
    var ul = child(d, el("ul", "evidence"));
    item.evidence.forEach(function (e) {
      var li = el("li");
      if (e.registry) {
        add(li, el("div", "frames", "From " + e.registry));
        add(li, el("div", null, e.detail));
        add(li, el("div", "meta", e.kind + " by " + e.decoder + ", file dated " + when(e.time)));
      } else {
        add(li, el("div", "frames", frameText(e.frames) + (e.source ? " in capture " + e.source : "")));
        add(li, el("div", null, e.detail));
        add(li, el("div", "meta", e.kind + " by " + e.decoder + ", " + when(e.time)));
      }
      ul.appendChild(li);
    });
    if (item.count > item.evidence.length) {
      add(d, el("p", "more", "Showing " + num(item.evidence.length) + " of " + num(item.count) + " records. Counts and times cover all of them."));
    }
    return d;
  }
  function valueRow(item, showValue) {
    var wrap = el("div", "value");
    if (showValue && item.value !== null && item.value !== undefined) add(wrap, el("div", null, item.value));
    var ev = evidenceList(item);
    add(wrap, ev || el("span", "count", plural(item.count, "record", "records")));
    return wrap;
  }
  function factsSection(fields) {
    var frag = document.createDocumentFragment();
    var unknown = [];
    fields.forEach(function (f) { if (f.items.length) frag.appendChild(fact(f)); else unknown.push(f.inline); });
    if (unknown.length) {
      var p = el("p", "none", "Not stated in the capture: " + unknown.join(", "));
      frag.appendChild(p);
    }
    return frag;
  }
  function fact(f) {
    var box = el("div", "fact" + (f.state === "conflict" ? " conflict" : ""));
    var label = f.state === "conflict" ? f.label + ": conflicting claims, all kept" : f.label;
    add(box, el("p", "label", label));
    if (!f.items.length) { add(box, el("p", "none", "Not stated in the capture")); return box; }
    f.items.forEach(function (it) { box.appendChild(valueRow(it, true)); });
    return box;
  }

  // ---------- panel views ----------
  function overview() {
    panel.textContent = "";
    add(panel, el("h2", null, plural(DATA.nodes.length, "asset", "assets")));
    add(panel, el("p", "sub", "Everything here is backed by frames in the capture. Select an asset to see what it did and the records behind it."));

    var byKind = {};
    DATA.nodes.forEach(function (n) { (byKind[n.kind] = byKind[n.kind] || []).push(n); });
    DATA.kinds.forEach(function (k) {
      var list = byKind[k.kind];
      if (!list) return;
      add(panel, el("h3", null, k.label + " (" + list.length + ")"));
      var ul = child(panel, el("ul", "assets"));
      list.sort(function (a, b) { return a.label.localeCompare(b.label, "en", { numeric: true }); });
      list.forEach(function (n) {
        var b = el("button");
        b.type = "button";
        add(b, symbol(n.kind), el("span", "name", n.label), el("span", "kindname", n.identity.split(":")[0] === "mac" ? "by MAC" : "by IP"));
        b.addEventListener("click", function () { select(n.id); });
        add(ul, add(el("li"), b));
      });
    });

    add(panel, el("h3", null, "Map key"));
    var key = child(panel, el("ul", "key"));
    DATA.kinds.concat([{ kind: "group", label: kindLabel.group }]).forEach(function (k) {
      add(key, add(el("li"), symbol(k.kind), el("span", null, k.label)));
    });
    add(key, add(el("li"), lineKey("l-ink"), el("span", null, "Answered requests, thicker means more")));
    add(key, add(el("li"), lineKey("l-write"), el("span", null, "Includes accepted Modbus writes")));
    add(key, add(el("li"), lineKey("l-rej"), el("span", null, "Modbus writes attempted, all rejected")));
    add(key, add(el("li"), lineKey("l-pub"), el("span", null, "Publishes to a multicast group")));

    add(panel, el("h3", null, "Seen but not turned into evidence"));
    if (!DATA.gaps.length) {
      add(panel, el("p", "empty", "Every decoded frame either became evidence or was not relevant to any decoder."));
    } else {
      DATA.gaps.forEach(function (g) {
        var p = el("p", "gap");
        add(p, el("span", "n", num(g.count)), el("span", null, g.text || "See the decoder documentation"));
        add(p, el("br"), el("span", "k", g.key));
        add(panel, p);
      });
    }

    if (DATA.lookups && DATA.lookups.length) {
      add(panel, el("h3", null, "Registry lookups"));
      DATA.lookups.forEach(function (g) {
        var p = el("p", "gap");
        add(p, el("span", "n", num(g.count)), el("span", null, g.text));
        add(panel, p);
      });
    }
    add(panel, el("h3", null, DATA.sources.length === 1 ? "Capture" : "Captures"));
    DATA.sources.forEach(function (s) {
      var p = el("p", "gap");
      add(p, el("span", null, plural(s.frame_count, "frame", "frames") + ", " + span(s.start, s.end).replace(/^Seen /, "")));
      add(p, el("br"), el("span", "k", "SHA-256 " + s.sha256));
      add(panel, p);
    });
    add(panel, el("p", "sub", "KeelMap " + DATA.tool_version + ", inventory schema " + DATA.schema_version));
  }

  function backButton() {
    var b = el("button", "link", "All assets");
    b.type = "button";
    b.addEventListener("click", function () { clearSelection(); overview(); });
    return b;
  }

  function nodeView(n) {
    panel.textContent = "";
    add(panel, backButton());
    add(panel, el("h2", null, n.label));
    add(panel, el("p", "sub", kindLabel[n.kind] + ", identified " + (n.identity.indexOf("mac:") === 0 ? "by MAC address" : "by IP address only")));
    add(panel, el("p", "sub", span(n.first_seen, n.last_seen)));

    add(panel, el("h3", null, "What it did"));
    if (!n.activities.length) add(panel, el("p", "empty", "Only its addresses were seen."));
    n.activities.forEach(function (a) {
      var box = el("div", "fact");
      add(box, el("p", "label", a.label));
      a.items.forEach(function (it) { box.appendChild(valueRow(it, true)); });
      add(panel, box);
    });

    add(panel, el("h3", null, "What it says about itself"));
    panel.appendChild(factsSection(n.about));

    add(panel, el("h3", null, "Addresses"));
    panel.appendChild(factsSection(n.addresses));

    var edges = DATA.edges.filter(function (e) { return e.source === n.id || e.target === n.id; });
    add(panel, el("h3", null, "Connections"));
    if (!edges.length) add(panel, el("p", "empty", "No two-way exchanges seen. One-way traffic such as NMEA over UDP does not prove a receiver."));
    edges.forEach(function (e) {
      var other = nodeById[e.source === n.id ? e.target : e.source];
      var text = e.kind === "publish"
        ? "Publishes to group " + other.label
        : (e.source === n.id ? "Sends " : "Answers ") + e.protocol + (e.source === n.id ? " requests to " : " requests from ") + other.label + ", " + plural(e.count, "exchange", "exchanges");
      var b = el("button", "conn", text);
      b.type = "button";
      b.addEventListener("click", function () { select(e.id); });
      add(panel, b);
    });
  }

  function edgeView(e) {
    panel.textContent = "";
    add(panel, backButton());
    var s = nodeById[e.source], t = nodeById[e.target];
    if (e.kind === "publish") {
      add(panel, el("h2", null, s.label + " publishes to " + t.label));
      add(panel, el("p", "sub", "Multicast destination. Receivers are not visible in a capture."));
      add(panel, valueRow({ value: null, count: e.count, evidence: e.evidence }, false));
      return;
    }
    add(panel, el("h2", null, s.label + " to " + t.label));
    add(panel, el("p", "sub", e.protocol + " over " + e.transport.toUpperCase() + (e.port ? " port " + e.port : "")));
    add(panel, el("p", "sub", plural(e.count, "answered exchange", "answered exchanges") + " in " + plural(e.packets, "frame", "frames") + ". " + span(e.first_seen, e.last_seen)));
    if (e.writes || e.rejected_writes) {
      var w = el("p", "sub");
      w.textContent = (e.writes ? num(e.writes) + " accepted writes" : "No accepted writes") + (e.rejected_writes ? ", " + num(e.rejected_writes) + " rejected write attempts" : "");
      add(panel, w);
    }
    add(panel, el("h3", null, "Operations"));
    e.operations.forEach(function (o) {
      var row = el("div", "op" + (o.write ? " write" : "") + (o.rejected ? " rejected" : ""));
      add(row, el("span", "text", o.text), el("span", "n", num(o.count)));
      add(panel, row, evidenceList(o, "Show records"));
    });
  }

  // ---------- chart ----------
  var cy = cytoscape({
    container: document.getElementById("cy"),
    elements: [],
    minZoom: 0.15, maxZoom: 3, wheelSensitivity: 0.3,
    boxSelectionEnabled: false
  });

  function elements() {
    var els = [];
    DATA.nodes.forEach(function (n) { els.push({ group: "nodes", data: { id: n.id, label: n.label, kind: n.kind } }); });
    DATA.groups.forEach(function (g) { els.push({ group: "nodes", data: { id: g.id, label: g.label, kind: "group", gw: 16 + g.label.length * 7.4 } }); });
    DATA.edges.forEach(function (e) {
      var cls = e.kind === "publish" ? "publish" : e.writes ? "write" : e.rejected_writes ? "rejected" : "";
      els.push({ group: "edges", classes: cls, data: {
        id: e.id, source: e.source, target: e.target,
        w: e.kind === "publish" ? 1.5 : Math.min(9, 1.5 + Math.log10(Math.max(1, e.count)) * 1.6)
      } });
    });
    return els;
  }

  function styles() {
    var ink = css("--ink"), soft = css("--ink-soft"), faint = css("--ink-faint"), water = css("--water"),
        paper = css("--paper"), magenta = css("--magenta"), buff = css("--buff"), buffEdge = css("--buff-edge"),
        green = css("--sea-green"), greenFill = css("--sea-green-fill");
    return [
      { selector: "node", style: {
        label: "data(label)", "font-family": css("--sans"), "font-size": 13, "min-zoomed-font-size": 7, color: ink,
        "text-valign": "bottom", "text-margin-y": 5, "text-wrap": "ellipsis", "text-max-width": 170,
        "text-outline-color": water, "text-outline-width": 3,
        width: 26, height: 26, "background-color": paper, "border-width": 1.5, "border-color": ink } },
      { selector: 'node[kind = "gateway"]', style: { shape: "diamond", width: 34, height: 34, "background-color": buff, "border-color": buffEdge } },
      { selector: 'node[kind = "server"]', style: { shape: "round-rectangle", width: 34, height: 26, "background-color": buff, "border-color": buffEdge } },
      { selector: 'node[kind = "ais"]', style: { shape: "vee", width: 30, height: 30, "background-color": greenFill, "border-color": green } },
      { selector: 'node[kind = "navigation"]', style: { shape: "triangle", width: 30, height: 28, "background-color": greenFill, "border-color": green } },
      { selector: 'node[kind = "infrastructure"]', style: { shape: "hexagon" } },
      { selector: 'node[kind = "network"]', style: { shape: "rectangle", width: 24, height: 24 } },
      { selector: 'node[kind = "device"]', style: { width: 16, height: 16, "border-color": faint } },
      { selector: 'node[kind = "group"]', style: {
        shape: "round-rectangle", width: "data(gw)", height: 28, "background-opacity": 0, "border-style": "dashed",
        "border-color": green, color: green, "text-valign": "center", "text-margin-y": 0, "text-outline-width": 0 } },
      { selector: "edge", style: {
        width: "data(w)", "line-color": soft, "target-arrow-color": soft, "target-arrow-shape": "triangle",
        "arrow-scale": 0.8, "curve-style": "bezier", opacity: 0.85 } },
      { selector: "edge.write", style: { "line-color": magenta, "target-arrow-color": magenta } },
      { selector: "edge.rejected", style: { "line-color": magenta, "target-arrow-color": magenta, "line-style": "dashed" } },
      { selector: "edge.publish", style: { "line-color": green, "target-arrow-color": green, "line-style": "dotted" } },
      { selector: ".faded", style: { opacity: 0.18 } },
      { selector: "node:selected", style: { "border-width": 3, "border-color": magenta } },
      { selector: "edge:selected", style: { "line-color": magenta, "target-arrow-color": magenta, opacity: 1 } }
    ];
  }

  function layout(done) {
    cy.layout({
      name: "cose", animate: false, randomize: true, nodeDimensionsIncludeLabels: true, fit: false,
      stop: done,
      idealEdgeLength: function () { return 140; }, nodeRepulsion: function () { return 12000; },
      componentSpacing: 90, padding: 60, numIter: 1500
    }).run();
  }

  // Fit into the area below the title block so no node hides behind it.
  function viewportFor(eles) {
    var bb = (eles || cy.elements()).boundingBox({ includeLabels: true });
    var box = document.querySelector(".cartouche").getBoundingClientRect();
    var host = document.getElementById("cy").getBoundingClientRect();
    var ctl = document.querySelector(".controls").getBoundingClientRect();
    var pad = 40, top = Math.min(box.bottom - host.top + 24, host.height * 0.45);
    // On narrow screens the search bar sits at the bottom of the chart, so keep clear of it too.
    var bottom = ctl.top - host.top > host.height / 2 ? host.bottom - ctl.top + 16 : pad;
    var w = host.width - 2 * pad, h = host.height - top - bottom;
    var zoom = Math.max(cy.minZoom(), Math.min(1.4, w / Math.max(bb.w, 1), h / Math.max(bb.h, 1)));
    return { zoom: zoom, pan: { x: pad + (w - bb.w * zoom) / 2 - bb.x1 * zoom, y: top + (h - bb.h * zoom) / 2 - bb.y1 * zoom } };
  }
  function fit(eles) {
    var v = viewportFor(eles);
    if (reduceMotion) cy.viewport(v); else cy.animate(Object.assign({ duration: 250 }, v));
  }

  function clearSelection() {
    cy.elements().unselect().removeClass("faded");
  }

  function select(id) {
    var ele = cy.getElementById(id);
    if (!ele || ele.empty()) return;
    cy.elements().unselect();
    ele.select();
    var hood = ele.isNode() ? ele.closedNeighborhood() : ele.union(ele.connectedNodes());
    cy.elements().addClass("faded");
    hood.removeClass("faded");
    if (ele.isNode()) {
      nodeById[id].kind === "group" ? groupView(nodeById[id]) : nodeView(nodeById[id]);
    } else {
      edgeView(DATA.edges.filter(function (e) { return e.id === id; })[0]);
    }
    panel.scrollTop = 0;
  }

  function groupView(g) {
    panel.textContent = "";
    add(panel, backButton());
    add(panel, el("h2", null, g.label));
    add(panel, el("p", "sub", "IEC 61162-450 multicast group. This is a destination, not a device."));
    add(panel, el("h3", null, "Publishers"));
    g.publishers.forEach(function (id) {
      var b = el("button", "conn", nodeById[id].label);
      b.type = "button";
      b.addEventListener("click", function () { select(id); });
      add(panel, b);
    });
  }

  cy.add(elements());
  cy.style(styles());
  // Labels are measured on first render, so place the view after it.
  function settle() { requestAnimationFrame(function () { requestAnimationFrame(function () { cy.viewport(viewportFor()); }); }); }
  layout(settle);
  var resizeTimer;
  window.addEventListener("resize", function () { clearTimeout(resizeTimer); resizeTimer = setTimeout(function () { cy.resize(); cy.viewport(viewportFor()); }, 150); });
  cy.on("tap", "node, edge", function (evt) { select(evt.target.id()); });
  cy.on("tap", function (evt) { if (evt.target === cy) { clearSelection(); overview(); } });

  document.getElementById("fit").addEventListener("click", function () { fit(); });
  var search = document.getElementById("search");
  search.addEventListener("input", function () {
    var q = search.value.trim().toLowerCase();
    cy.elements().removeClass("faded");
    if (!q) return;
    cy.nodes().forEach(function (node) {
      var n = nodeById[node.id()];
      var hay = n.search || (n.label || "").toLowerCase();
      if (hay.indexOf(q) === -1) node.addClass("faded");
    });
    cy.edges().addClass("faded");
  });
  search.addEventListener("keydown", function (ev) {
    if (ev.key !== "Enter") return;
    var hit = cy.nodes().filter(function (node) { return !node.hasClass("faded"); });
    if (hit.length) { select(hit[0].id()); fit(hit[0].closedNeighborhood()); }
  });

  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function () { cy.style(styles()); });

  // cartouche
  var dates = DATA.sources.map(function (s) { return s.start; }).filter(Boolean).sort();
  var ends = DATA.sources.map(function (s) { return s.end; }).filter(Boolean).sort();
  var summary = plural(DATA.frames_read, "frame", "frames") + " from " + plural(DATA.sources.length, "capture", "captures");
  if (dates.length) summary += ", " + span(dates[0], ends[ends.length - 1]).replace(/^Seen /, "").replace(/^once, /, "");
  document.getElementById("summary").textContent = summary;
  var red = document.getElementById("redaction");
  if (DATA.redacted) {
    red.textContent = "Vessel identifiers and file names are redacted.";
  } else {
    red.textContent = "Contains vessel identifiers. Share only with people cleared to see them.";
    red.classList.add("unredacted");
  }
  overview();
})();
