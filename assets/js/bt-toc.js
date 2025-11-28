(function () {
  function slugify(s) {
    return (s || "")
      .toLowerCase()
      .trim()
      .replace(/[\s]+/g, "-")
      .replace(/[^\w\-]+/g, "")
      .replace(/\-\-+/g, "-");
  }

  function buildTOC() {
    const main = document.querySelector(".main-content");
    if (!main) return;

    // Only show TOC on pages with a writeup container
    const scope = main.querySelector(".writeup");
    if (!scope) return;

    // Include all headings inside the content, grouped by level
    const headings = Array.from(scope.querySelectorAll("h1, h2, h3, h4, h5"))
      .filter(h => h.textContent && h.textContent.trim().length > 0);

    if (headings.length < 2) return; // not enough structure to show TOC

    // Ensure IDs exist
    const used = new Set();
    headings.forEach(h => {
      if (!h.id) {
        let base = slugify(h.textContent);
        let id = base || "section";
        let i = 2;
        while (used.has(id) || document.getElementById(id)) {
          id = `${base}-${i++}`;
        }
        h.id = id;
      }
      used.add(h.id);
    });

    // Build nested list from heading levels
    const toc = document.createElement("aside");
    toc.className = "bt-toc";
    toc.innerHTML = `<div class="bt-toc-title">Contents</div>`;
    const rootUl = document.createElement("ul");
    toc.appendChild(rootUl);

    const stack = [{ level: 0, ul: rootUl }];
    headings.forEach(h => {
      const level = parseInt(h.tagName.substring(1), 10); // 1-5
      const li = document.createElement("li");
      li.className = `lvl-${level}`;
      const a = document.createElement("a");
      a.href = `#${h.id}`;
      a.textContent = h.textContent.trim();
      li.appendChild(a);

      // find parent list for this level
      while (stack.length && level <= stack[stack.length - 1].level) {
        stack.pop();
      }
      const parent = stack[stack.length - 1].ul;
      parent.appendChild(li);

      // prepare for potential children
      const childUl = document.createElement("ul");
      li.appendChild(childUl);
      stack.push({ level, ul: childUl });
    });

    document.body.appendChild(toc);

    // Active section highlight
    const links = Array.from(toc.querySelectorAll("a"));
    const map = new Map(links.map(a => [a.getAttribute("href").slice(1), a]));

    const obs = new IntersectionObserver((entries) => {
      const visible = entries
        .filter(e => e.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
      if (!visible) return;

      links.forEach(a => a.classList.remove("bt-active"));
      const active = map.get(visible.target.id);
      if (active) active.classList.add("bt-active");
    }, { rootMargin: "-15% 0px -75% 0px", threshold: [0.05, 0.2, 0.5, 1.0] });

    headings.forEach(h => obs.observe(h));
  }

  function enableImageZoom() {
    const images = Array.from(document.querySelectorAll(".main-content img"));
    if (!images.length) return;

    const overlay = document.createElement("div");
    overlay.className = "bt-zoom-overlay";
    overlay.innerHTML = `<img alt=""><button class="bt-zoom-close" aria-label="Close zoomed image">×</button>`;
    document.body.appendChild(overlay);
    const overlayImg = overlay.querySelector("img");
    const closeBtn = overlay.querySelector(".bt-zoom-close");

    function close() {
      overlay.classList.remove("active");
      document.body.classList.remove("bt-zoom-open");
    }

    overlay.addEventListener("click", (e) => {
      if (e.target === overlay || e.target === closeBtn) close();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && overlay.classList.contains("active")) close();
    });

    images.forEach(img => {
      img.classList.add("bt-zoomable");
      img.addEventListener("click", () => {
        overlayImg.src = img.src;
        overlayImg.alt = img.alt || "";
        overlay.classList.add("active");
        document.body.classList.add("bt-zoom-open");
      });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      buildTOC();
      enableImageZoom();
    });
  } else {
    buildTOC();
    enableImageZoom();
  }
})();
