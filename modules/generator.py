import math
from utils.html_utils import extract_html

GENERATION_MODEL = "claude-sonnet-4.6"

SYSTEM_PROMPT = """You are a senior Mozilla Gecko engine security researcher specializing in memory corruption vulnerabilities. Your goal is to write fuzz test cases that trigger use-after-free, heap overflow, type confusion, and other memory safety bugs in Firefox — NOT simple hangs or timeouts.

You understand:
- DOM object lifecycle: when nodes are removed, adopted, or moved, internal C++ pointers can become dangling
- CSS layout re-entrancy: forced reflows during callbacks can access freed layout frames
- JavaScript engine: JIT compilation, type confusion between objects, GC-observable side effects
- SVG/Canvas/WebGL: native-code backing stores that can be detached or resized during use
- Web APIs with C++ backing: WebRTC, Web Audio, IndexedDB — JS wrappers can outlive native objects
- Parser re-entrancy: innerHTML/document.write during parsing can corrupt parser state

Critical patterns that find real vulnerabilities:
1. Remove a DOM node, then immediately access its layout properties or children
2. Trigger GC (via large allocation) while a C++ pointer to a JS object is on the stack
3. Use requestAnimationFrame + setTimeout to race DOM mutation against layout/paint
4. Resize/detach ArrayBuffers while TypedArrays reference them
5. Swap iframe documents while event handlers are executing on the old document
6. Cause CSS style invalidation during font loading callbacks or IntersectionObserver
7. Call Web Audio/WebGL methods on contexts that are being closed

DO NOT generate test cases that merely create deep nesting or layout thrashing — those only cause timeouts, which are low-value DoS. Focus on patterns that corrupt memory.

Always output raw HTML only. No markdown, no code fences, no explanations outside of HTML comments."""

STRATEGIES = {
    "use_after_free": {
        "prompt": "Generate a test case targeting USE-AFTER-FREE in DOM: remove a node from the DOM tree, then immediately trigger operations that reference it — access its .parentNode, read its .offsetHeight (forces layout on a freed frame), dispatch events to it, or use it as an argument to Range/Selection APIs. Use setTimeout(0) and MutationObserver to create timing where the C++ destructor runs before JS finishes.",
        "uses": 0,
        "crashes": 0,
    },
    "gc_pressure": {
        "prompt": "Generate a test case that triggers GARBAGE COLLECTION at dangerous moments: allocate large ArrayBuffers to force GC, then immediately access DOM nodes, CSS computed styles, or canvas image data that may have been moved by the GC. Interleave GC-triggering allocations with WebGL texture uploads, AudioBuffer operations, or OffscreenCanvas transfers.",
        "uses": 0,
        "crashes": 0,
    },
    "type_confusion": {
        "prompt": "Generate a test case targeting TYPE CONFUSION in SpiderMonkey: use Object.defineProperty to change getters/setters on prototype chains during JIT-compiled hot loops, convert between ArrayBuffer and SharedArrayBuffer views, abuse Proxy traps that return unexpected types, and trigger deoptimization while typed arrays are being accessed. Force the JIT to make wrong assumptions about object shapes.",
        "uses": 0,
        "crashes": 0,
    },
    "layout_uaf": {
        "prompt": "Generate a test case targeting USE-AFTER-FREE in CSS LAYOUT: trigger reflow callbacks (ResizeObserver, IntersectionObserver, scroll events) that mutate the DOM tree during layout computation. Remove elements that have pending CSS transitions or animations. Change display types during font-load callbacks. Force style recalculation on elements being removed by adoptNode or replaceChild.",
        "uses": 0,
        "crashes": 0,
    },
    "buffer_detach": {
        "prompt": "Generate a test case targeting ARRAYBUFFER DETACHMENT: create TypedArrays backed by ArrayBuffers, then detach the buffer via postMessage transfer or WebAssembly.Memory growth while the TypedArray is being iterated. Use DataView on transferred buffers. Resize SharedArrayBuffers while Atomics operations are pending. Transfer ImageBitmap/OffscreenCanvas ownership while drawing.",
        "uses": 0,
        "crashes": 0,
    },
    "iframe_lifecycle": {
        "prompt": "Generate a test case targeting IFRAME DOCUMENT LIFECYCLE bugs: create iframes, access their contentDocument, then remove the iframe while still holding references to its DOM nodes, events, or Window object. Navigate iframes via src changes during load events. Call document.write on iframe documents during the parent's unload. Race iframe removal against postMessage delivery.",
        "uses": 0,
        "crashes": 0,
    },
    "web_api_native": {
        "prompt": "Generate a test case targeting NATIVE CODE boundaries in Web APIs: close a WebGL context then call draw methods, disconnect Web Audio nodes during processing callbacks, abort IndexedDB transactions while cursors are iterating, close WebSocket/RTCPeerConnection during message delivery. These APIs have C++ implementations where the JS wrapper can outlive the native object.",
        "uses": 0,
        "crashes": 0,
    },
}


def select_strategy() -> tuple:
    """Select a strategy using UCB1 multi-armed bandit algorithm."""
    total_uses = sum(s["uses"] for s in STRATEGIES.values())
    best_name = None
    best_score = -1.0

    for name, s in STRATEGIES.items():
        if s["uses"] == 0:
            return name, s["prompt"]
        crash_rate = s["crashes"] / max(s["uses"], 1)
        exploration = math.sqrt(2 * math.log(total_uses + 1) / max(s["uses"], 1))
        score = crash_rate + exploration
        if score > best_score:
            best_score = score
            best_name = name

    return best_name, STRATEGIES[best_name]["prompt"]


def record_result(strategy_name: str, found_crash: bool):
    """Update strategy stats after a test run."""
    if strategy_name in STRATEGIES:
        STRATEGIES[strategy_name]["uses"] += 1
        if found_crash:
            STRATEGIES[strategy_name]["crashes"] += 1


def generate_test_case(client, history, strategy_name, strategy_prompt, subsystem_hint=None):
    """Generate a test case using the LLM with strategy and subsystem context."""
    user_content = strategy_prompt
    if subsystem_hint:
        hint_str = ", ".join(subsystem_hint) if isinstance(subsystem_hint, list) else subsystem_hint
        user_content += f"\n\nFocus especially on these underexplored subsystems: {hint_str}"

    messages = history + [{"role": "user", "content": user_content}]

    print(f"  [DEBUG] Calling {GENERATION_MODEL} with {len(messages)} messages ({sum(len(str(m.get('content',''))) for m in messages)} chars)...")
    t0 = __import__('time').time()
    response = client.messages.create(
        model=GENERATION_MODEL,
        max_tokens=16384,
        system=SYSTEM_PROMPT,
        messages=messages
    )
    elapsed = __import__('time').time() - t0
    raw_content = response.content[0].text
    print(f"  [DEBUG] Response received in {elapsed:.1f}s ({len(raw_content)} chars)")
    html_content = extract_html(raw_content)

    new_history = messages + [{"role": "assistant", "content": raw_content}]

    return new_history, html_content
