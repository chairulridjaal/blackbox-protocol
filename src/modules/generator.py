import math
import threading
from utils.html_utils import extract_html

GENERATION_MODEL = "claude-sonnet-4.5"

SYSTEM_PROMPT = """You are an elite red-team browser security researcher. You have discovered multiple CVEs in Gecko/Firefox and have been paid six-figure bounties from Mozilla. You think like an attacker: you study the C++ source on Searchfox, identify invariants the developers assume will hold, then craft minimal HTML/JS that violates those invariants at the exact moment a raw pointer or unguarded reference is live.

Your test cases are NOT random fuzz — they are surgical. Every line of code exists to set up, trigger, or amplify a specific memory safety violation. You never write "exploratory" code or hope for the best. You construct a precise sequence of API calls that puts Gecko into a state its developers did not anticipate.

## YOUR MENTAL MODEL OF GECKO INTERNALS

You know these C++ systems intimately:

**DOM / Layout (nsIFrame, PresShell, FrameManager):**
- nsIFrame pointers are cached across reflows. Removing a node schedules frame destruction, but JS callbacks can fire between scheduling and destruction — accessing offsetHeight/getBoundingClientRect on the node during this window reads freed memory.
- PresShell::FlushPendingNotifications triggers frame construction/destruction synchronously. Calling it from inside a MutationObserver or ResizeObserver creates re-entrancy that the frame tree does not expect.
- adoptNode() and insertBefore() can move nodes between documents while layout holds pointers to their frames in the source document.

**SpiderMonkey JIT (IonMonkey/Warp, Range Analysis, Type Inference):**
- The JIT performs range analysis to eliminate bounds checks. If you can make the range analysis believe an index is in-bounds when it isn't (e.g., by exploiting integer overflow in range propagation, or by changing array length after JIT compilation), you get OOB read/write. This exact pattern was CVE-2024-29943 ($100K Pwn2Own).
- Type inference tracks object shapes. If you train a function on one shape then pass a different shape, the JIT may use the wrong offset for property access — type confusion.
- The `with` statement creates scope chains that confuse property resolution. CVE-2024-8381 was a type confusion from property lookup on `document.body` used as `with` environment.

**Animation Timeline (AnimationTimeline, Animation, KeyframeEffect):**
- CVE-2024-9680 (CVSS 9.8, exploited in the wild by RomCom APT): Animation objects are stored in a timeline. Accessing the `.ready` promise with a getter that cancels animations and removes DOM elements causes AnimationTimeline::Tick() to iterate over freed Animation pointers.
- The pattern: create animations, set up a callback that fires during timeline tick, destroy the animated elements from inside that callback.

**XSLT / XPath (XSLTProcessor, txXPathNodeUtils):**
- Ivan Fratric (Google Project Zero) found UAFs in XSLTProcessor in BOTH Firefox 135 AND 137 (CVE-2025-1009, CVE-2025-3028). This is old C++ code with complex object lifecycle.
- XSLT transformations create temporary node trees. If you modify or destroy the source document during transformation callbacks, the XPath evaluation reads freed nodes.
- XSLTProcessor.transformToFragment() with manipulated source documents and stylesheets.

**WebAssembly (StructFields, i31ref, Exception Handling):**
- CVE-2024-8385: type confusion between WASM StructFields and ArrayTypes when using GC proposal types (i31ref, structref, arrayref).
- CVE-2025-1933: WASM i32 return values on 64-bit CPUs can leak leftover bits from stack-spilled values.
- CVE-2024-7521: UAF in WASM exception handling when exceptions reference freed objects.

**GC / Cycle Collector (SpiderMonkey GC, CycleCollector):**
- The GC assumes certain pointers are traced. If a C++ destructor runs between GC marking and sweeping, and the destructor nulls a pointer the GC expects to find, you get a dangling reference.
- Concurrent delazification (CVE-2025-1012): SpiderMonkey lazily compiles functions. If two threads race to delazify the same function, internal state corruption occurs.
- OOM during JIT compilation (CVE-2024-9400): JIT OOM handling can leave the engine in an inconsistent state.

**IPC / Sandbox (IPDL, IPC handles):**
- CVE-2025-2857: incorrect handle passed in IPC allows sandbox escape. Same pattern as Chrome's CVE-2025-2783.
- AudioIPC StreamData (CVE-2025-1930): UAF when IPC messages arrive during audio stream teardown.
- WebTransportChild (CVE-2025-1931): UAF in child process WebTransport lifecycle.

**IndexedDB + GC:**
- CVE-2024-7528: UAF when IndexedDB operations interact with GC timing. The IDB cursor holds references that become stale after GC.

**Custom Highlight API / DOM APIs:**
- CVE-2025-1010: UAF in Custom Highlight API (CSS.highlights, Highlight constructor + range manipulation). New APIs have thin coverage.
- CVE-2024-7522: OOB in Editor attribute validation.

## REAL CVE PATTERNS — USE AS TEMPLATES AND MUTATE

PATTERN A — Animation Timeline UAF (CVE-2024-9680):
```javascript
let div = document.createElement('div');
document.body.appendChild(div);
let anim = div.animate([{opacity:0},{opacity:1}], {duration:1000});
// The .ready getter fires during timeline tick — destroy the element there
Object.defineProperty(anim, 'ready', { get() {
    anim.cancel();
    div.remove();
    // Timeline still iterates over freed Animation*
}});
```

PATTERN B — JIT Range Analysis Bypass (CVE-2024-29943):
```javascript
function exploit(arr, idx) {
    if (idx >= 0 && idx < arr.length) {
        return arr[idx]; // JIT eliminates bounds check
    }
}
for (let i = 0; i < 100000; i++) exploit([1,2,3], i % 3);
let a = [1,2,3]; a.length = 1;
exploit(a, 2); // OOB — JIT uses stale range analysis
```

PATTERN C — XSLT UAF (CVE-2025-1009/3028):
```javascript
let xslt = new XSLTProcessor();
let style = new DOMParser().parseFromString(
    '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">' +
    '<xsl:template match="/"><xsl:copy-of select="//node()"/></xsl:template></xsl:stylesheet>',
    'text/xml');
xslt.importStylesheet(style);
let src = new DOMParser().parseFromString('<root><child/></root>', 'text/xml');
let frag = xslt.transformToFragment(src, document);
```

PATTERN D — with-Statement Type Confusion (CVE-2024-8381):
```javascript
with (document.body) {
    let x = firstChild; // Type confusion in property resolution
}
```

PATTERN E — Re-entrant Callback During Iteration:
```javascript
element.addEventListener('DOMNodeRemoved', () => {
    element.parentNode.removeChild(siblingElement);
    // C++ iterator now holds stale pointer
});
```

PATTERN F — GC During Raw Pointer Use:
```javascript
let nodes = Array.from({length:5000}, () => document.createElement('div'));
nodes.forEach(n => document.body.appendChild(n));
let pressure = new ArrayBuffer(50 * 1024 * 1024); // force GC
nodes.forEach(n => n.getBoundingClientRect()); // stale C++ pointers
```

## WHAT SEPARATES YOUR TEST CASES FROM AMATEUR FUZZ

1. You target a SPECIFIC C++ class and method (e.g., "nsIFrame::GetRectRelativeToSelf after FrameManager::DestroyFramesFor")
2. You CREATE the precondition that makes the invariant violation possible (e.g., "MutationObserver fires between RemoveFrame scheduling and execution")
3. You TRIGGER the violation at the exact right moment (e.g., "force layout via offsetHeight inside the callback")
4. You AMPLIFY the consequence (e.g., "spray ImageData to fill the freed slot, then read back")

## OUTPUT RULES

- Output raw HTML ONLY. No markdown, no code fences, no explanations outside HTML comments.
- Every test case MUST include a top comment block:
  <!--
    Target: [specific Gecko C++ class/method]
    Property: [what invariant is being violated]
    Mechanism: [step-by-step how the violation is triggered]
    Expected: [specific ASan/crash signature expected]
  -->
- Keep under 250 lines total. Use every line to build the precise preconditions needed.
- For JIT bugs: use 50,000–100,000 iterations to ensure IonMonkey/Warp reaches the optimizing tier before delivering the payload. The JIT will NOT compile to optimized code with fewer iterations.
- All loops MUST have explicit upper bounds (no infinite loops or unbounded recursion).
- One surgical attack per test — deep, not wide.
- NEVER generate pure resource exhaustion (deep nesting, layout thrashing). Focus on memory safety invariant violations.
- NEVER repeat a pattern you already generated — always mutate aggressively."""

STRATEGIES = {
    "use_after_free": {
        "prompt": "Generate a test case targeting USE-AFTER-FREE in DOM node lifecycle. Focus on the window between node removal and frame destruction. Key C++ targets: nsIFrame pointers cached across reflows, pointers held by Range/Selection APIs across DOM mutations, event listeners accessing nodes after removeChild. Key patterns: (1) Remove a node via removeChild, then force layout with offsetHeight/getBoundingClientRect from inside a MutationObserver callback — the nsIFrame may already be on the destroy list. (2) Use Range.setStartBefore on a node, remove the node, then call Range.getBoundingClientRect — RangeUtils walks a freed frame tree. (3) Hold a Selection across adoptNode — the selection's anchor node moves documents but nsFrameSelection keeps the old frame pointer. (4) Dispatch events to removed nodes — EventStateManager walks the freed frame tree for bubble routing. (5) Call getComputedStyle on a node removed during a requestAnimationFrame callback. Target: nsIFrame::GetRectRelativeToSelf, RangeUtils::CompareNodeToRange, PresShell::FlushPendingNotifications. Your output must include the top comment block.",
        "uses": 0,
        "crashes": 0,
    },
    "gc_pressure": {
        "prompt": "Generate a test case that triggers GARBAGE COLLECTION at the exact moment C++ holds untraced raw pointers. Key patterns: (1) allocate large ArrayBuffers (50MB+) to force GC, then immediately call getBoundingClientRect/getComputedStyle on DOM nodes whose C++ pointers may have moved. (2) Interleave GC-triggering allocations with WebGL texture uploads or AudioBuffer operations. (3) Use FinalizationRegistry to detect when objects are collected, then access stale references. (4) CVE-2024-7527 pattern: trigger GC marking phase, then mutate the object graph so the sweep phase frees a still-referenced object. Target: SpiderMonkey GC (js::gc::GCRuntime), CycleCollector, Zone::sweep. Your output must include the top comment block.",
        "uses": 0,
        "crashes": 0,
    },
    "type_confusion": {
        "prompt": "Generate a test case targeting TYPE CONFUSION in SpiderMonkey JIT. Key patterns: (1) Train a function on one object shape, then pass a different shape to trigger JIT deoptimization with stale type assumptions. (2) Use Object.defineProperty to swap getters/setters on prototype chains during hot loops. (3) Abuse Proxy traps that return unexpected types during JIT-compiled property access. (4) CVE-2024-8381 pattern: use `with(document.body)` to create scope chains that confuse property resolution type inference. (5) Force shape transitions during array operations — change element kinds from packed to holey during iteration. Target: IonMonkey type inference, Shape/BaseShape corruption, JIT code cache invalidation. Your output must include the top comment block.",
        "uses": 0,
        "crashes": 0,
    },
    "layout_uaf": {
        "prompt": "Generate a test case targeting USE-AFTER-FREE in CSS LAYOUT engine re-entrancy. Key patterns: (1) Trigger ResizeObserver/IntersectionObserver callbacks that call removeChild on elements whose nsIFrame is currently being traversed by PresShell::DoReflow. (2) Force style recalculation during adoptNode/replaceChild — the old document's frame tree is destroyed while layout holds pointers. (3) Change CSS display property during font-load callbacks — triggers frame reconstruction while FlushPendingNotifications is on the stack. (4) Use CSS containment (contain: strict) with dynamic reparenting — the containment boundary invalidation races with frame destruction. Target: PresShell::FlushPendingNotifications, FrameManager::DestroyFramesFor, nsFrame::GetRectRelativeToSelf. Your output must include the top comment block.",
        "uses": 0,
        "crashes": 0,
    },
    "buffer_detach": {
        "prompt": "Generate a test case targeting ARRAYBUFFER DETACHMENT during active use. Key patterns: (1) Create a TypedArray, start iterating it, then transfer the backing ArrayBuffer via postMessage — the iteration reads freed memory. (2) Grow WebAssembly.Memory while a TypedArray view of its buffer is being accessed. (3) Use DataView methods on a buffer that was transferred in the same microtask. (4) Resize SharedArrayBuffers while Atomics.wait is pending on another thread (via Worker). (5) Transfer ImageBitmap ownership via createImageBitmap then read pixels. Target: js::ArrayBufferObject::detach, TypedArrayObject::setBufferAndLength, DataViewObject::getBuffer. Your output must include the top comment block.",
        "uses": 0,
        "crashes": 0,
    },
    "iframe_lifecycle": {
        "prompt": "Generate a test case targeting IFRAME DOCUMENT LIFECYCLE bugs. Key patterns: (1) Hold references to iframe.contentDocument nodes, remove the iframe, then access those nodes — the backing C++ objects (nsIDocument, nsINode) may be freed. (2) Navigate an iframe via src change during its load event — the old document's destructor races with the load event handler. (3) Use document.write on an iframe's contentDocument during the parent document's beforeunload — re-entrant parser state. (4) PostMessage to an iframe, then remove it before the message arrives — the message dispatch accesses a freed Window object. (5) Access iframe.contentWindow.performance / iframe.contentWindow.crypto after iframe removal. Target: nsGlobalWindowInner pointers, nsDocument pointers, BrowsingContext lifecycle. Your output must include the top comment block.",
        "uses": 0,
        "crashes": 0,
    },
    "web_api_native": {
        "prompt": "Generate a test case targeting NATIVE CODE boundaries where JS wrappers outlive their C++ backing objects. Key patterns: (1) Close a WebGL2RenderingContext then call draw/read methods — the C++ GLContext is destroyed but the JS wrapper is live. (2) Disconnect AudioNodes during processing callbacks (audioprocess event) — the C++ AudioNodeEngine is freed mid-callback. (3) Abort an IndexedDB transaction while a cursor is iterating — the C++ backing store is released while the JS cursor holds a pointer. (4) Close WebSocket during onmessage — the C++ WebSocketChannel is torn down during event dispatch. (5) CVE-2025-1930 pattern: send IPC messages to AudioIPC StreamData during stream teardown. Target: WebGL GLContext pointers, AudioNodeEngine pointers, IDBCursor backing store. Your output must include the top comment block.",
        "uses": 0,
        "crashes": 0,
    },
    "animation_lifecycle": {
        "prompt": "Generate a test case targeting the WEB ANIMATIONS API lifecycle — the same attack surface as CVE-2024-9680 (CVSS 9.8, exploited in the wild). Key patterns: (1) Create Animation objects linked to DOM elements, then cancel/remove them from inside a callback that fires during AnimationTimeline::Tick iteration. (2) Use the Animation.ready promise with a custom getter that destroys the animated element — the timeline still holds a pointer to the freed Animation. (3) Race Animation.finish() against element removal — the finish event handler accesses the freed KeyframeEffect. (4) Use CSS animations + Web Animations API simultaneously on the same element, then remove it during a transition event — the two animation systems disagree about ownership. (5) Call Animation.persist() on an animation whose target has been adopted into another document. Target: AnimationTimeline::Tick, Animation pointers in sorted lists, KeyframeEffect::mTarget. Your output must include the top comment block.",
        "uses": 0,
        "crashes": 0,
    },
    "xslt_xpath": {
        "prompt": "Generate a test case targeting XSLT/XPath PROCESSING — Ivan Fratric (Google Project Zero) found UAFs here in both Firefox 135 AND 137 (CVE-2025-1009, CVE-2025-3028). Key patterns: (1) Use XSLTProcessor.importStylesheet() + transformToFragment(), then modify or destroy the source document before transformation completes — txXPathNodeUtils reads freed nodes. (2) Create recursive XSLT templates that generate large intermediate node trees, then abort via exceptions — the cleanup path misses references. (3) Use XPath expressions with predicates that trigger callbacks that modify the document being queried. (4) Transform a document, then immediately transform again using the result of the first transformation — the temporary trees may be freed prematurely. (5) Use xsl:sort with a comparator that modifies the node set during sorting (CVE-2025-1932 pattern). Target: XSLTProcessor, txXPathNodeUtils, txMozillaTextOutput, XPathExpression evaluation. Your output must include the top comment block.",
        "uses": 0,
        "crashes": 0,
    },
    "wasm_type_boundary": {
        "prompt": "Generate a test case targeting WEBASSEMBLY TYPE BOUNDARIES — multiple CVEs in WASM type handling (CVE-2024-8385, CVE-2024-7521, CVE-2025-1933). Key patterns: (1) Create WASM modules with GC proposal types (structref, arrayref, i31ref) and construct values that cross type boundaries — the type checker may not catch all invalid casts. (2) Throw and catch WASM exceptions where the exception payload references objects that have been freed by GC. (3) Use WASM function references (funcref, externref) across module boundaries where the types don't match. (4) Compile modules with complex type hierarchies using rtt (runtime type information) casts that the JIT optimizes incorrectly. (5) CVE-2025-1933 pattern: call WASM functions that return i32 values on 64-bit CPUs where upper bits of the return register contain leftover stack data. Target: WasmStructObject, WasmArrayObject, i31ref boxing/unboxing, exception handling unwinder. Your output must include the top comment block.",
        "uses": 0,
        "crashes": 0,
    },
    "jit_range_analysis": {
        "prompt": "Generate a test case targeting SPIDERMONKEY JIT RANGE ANALYSIS — the same bug class as CVE-2024-29943 ($100K Pwn2Own). Key patterns: (1) Create a function with an index variable that the JIT proves is in-bounds via range analysis, then violate that proof by changing array length after JIT compilation. (2) Use integer overflow in range propagation — the JIT tracks ranges as (min, max) and overflow can make min > max, causing it to believe any value is valid. (3) Exploit phi-node range widening in loops — the JIT widens ranges at loop headers, and carefully crafted loop bounds can cause the widened range to include OOB values. (4) Use OSR (on-stack replacement) entry points where the range state from the interpreter doesn't match JIT assumptions. (5) Trigger bailout and re-optimization with values that invalidate previously computed ranges. Target: Range Analysis pass, BoundsCheck elimination, MBoundsCheck::foldsTo, RangeAnalysis::analyzeLoop. Your output must include the top comment block.",
        "uses": 0,
        "crashes": 0,
    },
    "integer_overflow": {
        "prompt": "Generate a test case targeting INTEGER OVERFLOW in graphics/layout math. Key pattern: DIFFERENTIAL BOUNDS CHECKING — outer functions use safe conversion (GfxRectToIntRect, CheckedInt) but inner functions use unsafe (RoundedToInt, direct cast). Key patterns: (1) SVG filter: region='0,0,100,100' passes top-level check, but <feFlood x='2147483600' width='2147483600'/> overflows in ComputeFilterPrimitiveSubregion→RoundedToInt, resulting in tiny allocation but large write offset. (2) Canvas: width=100 passes validation, but createImageData(width*multiplier*4) overflows allocation math, allocates small buffer, writes to large offset. (3) CSS Grid: small explicit grid passes check, but auto-placed items cause dimension overflow in nsGridContainerFrame. (4) Image decode: width and height validated separately, but width*height*4 overflows buffer calculation. (5) Font metrics: glyph bounds x/y near INT32_MAX overflow in gfxFont::GetGlyphBounds calculation. Use INT32_MAX-epsilon values (2147483600, 0x7FFFFFF0) to pass outer checks but trigger nested overflow. Chain operations: safe outer call → unsafe nested conversion → corrupted IntRect → buffer allocation → OOB write. Target C++: SVGFilterInstance::ComputeFilterPrimitiveSubregion (RoundedToInt), FilterSupport::RenderFilterDescription, CanvasRenderingContext2D::CreateImageData, nsGridContainerFrame dimension calculation, ImageDecoder buffer allocation, gfxFont::GetGlyphBounds. Expected: ASan heap-buffer-overflow on write to undersized buffer. Your output must include the top comment block.",
        "uses": 0,
        "crashes": 0,
    },
}

_strategy_lock = threading.Lock()


def select_strategy() -> tuple:
    """Select a strategy using UCB1 multi-armed bandit algorithm.

    Atomically claims the selected strategy by incrementing its uses counter
    under the lock, preventing multiple workers from selecting the same one.
    """
    with _strategy_lock:
        total_uses = sum(s["uses"] for s in STRATEGIES.values())
        best_name = None
        best_score = -1.0

        for name, s in STRATEGIES.items():
            if s["uses"] == 0:
                s["uses"] += 1  # Claim atomically
                return name, s["prompt"]
            crash_rate = s["crashes"] / max(s["uses"], 1)
            exploration = math.sqrt(2 * math.log(total_uses + 1) / max(s["uses"], 1))
            score = crash_rate + exploration
            if score > best_score:
                best_score = score
                best_name = name

        STRATEGIES[best_name]["uses"] += 1  # Claim atomically
        return best_name, STRATEGIES[best_name]["prompt"]


def record_result(strategy_name: str, found_crash: bool):
    """Record crash result for a strategy (uses already counted at selection time)."""
    with _strategy_lock:
        if strategy_name in STRATEGIES and found_crash:
            STRATEGIES[strategy_name]["crashes"] += 1


def generate_test_case(client, history, strategy_name, strategy_prompt, subsystem_hint=None):
    """Generate a test case using the LLM with strategy and subsystem context."""
    # Build user content with subsystem targeting at the start
    user_content = ""
    if subsystem_hint:
        hint_str = ", ".join(subsystem_hint) if isinstance(subsystem_hint, list) else subsystem_hint
        user_content = f"[TARGET SUBSYSTEM: {hint_str}]\n\n"

    user_content += strategy_prompt

    messages = history + [{"role": "user", "content": user_content}]

    print(f"  [DEBUG] Calling {GENERATION_MODEL} with {len(messages)} messages ({sum(len(str(m.get('content',''))) for m in messages)} chars)...")
    t0 = __import__('time').time()
    response = client.messages.create(
        model=GENERATION_MODEL,
        max_tokens=16384,
        system=[{
            "type": "text",
            "text": SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"}
        }],
        messages=messages
    )
    elapsed = __import__('time').time() - t0
    if not response.content:
        raise ValueError(f"API returned empty response (no content blocks) after {elapsed:.1f}s")
    raw_content = response.content[0].text
    print(f"  [DEBUG] Response received in {elapsed:.1f}s ({len(raw_content)} chars)")
    html_content = extract_html(raw_content)

    # Create summary for history instead of storing full HTML
    subsystem_str = subsystem_hint[0] if subsystem_hint and isinstance(subsystem_hint, list) and len(subsystem_hint) > 0 else (subsystem_hint if subsystem_hint else "unknown")
    summary = f"[Generated {len(html_content)} char HTML targeting {subsystem_str} via {strategy_name}. Key techniques: {html_content[:200]}...]"
    new_history = messages + [{"role": "assistant", "content": summary}]

    return new_history, html_content
