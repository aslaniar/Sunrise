#include "milestone_trace_observer.h"

#include <Windows.h>
#include <intrin.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../../diagnostics/module_range.h"
#include "../../hooking/detour.h"
#include "../gate_wwatch/gate_wwatch.h"

namespace sunrise::client::hooks::milestone_trace {
namespace {

/**
 * One traced function. Every RVA here is a .pdata function START, checked by
 * RE_scripts/verify_hook_rvas.py - the 20.112 trap (a range check passes on a WRONG
 * address and the detour silently attaches to an unrelated function) is why that gate
 * exists and why nothing goes in this table unverified.
 */
/**
 * Structured memory probes (p2-144). A probe reads NAMED FIELDS of the callee's own
 * argument at entry and again at leave, so a mask that fills or empties across one call
 * is visible as a DELTA rather than inferred. Every read is null-guarded and every
 * chase mirrors one the callee itself performs at that exact point, so the pointer is
 * as proven as the game's own use of it (the read-after-return rule generalised).
 */
/** Which argument register a callee writes its result through. See Target::out_param. */
enum class OutParam : std::uint8_t {
    none = 0,
    rdx,  ///< `mov [rdx], ...` at entry - e.g. idx_alloc 0x141711D10
    rcx,  ///< `mov [rcx], ...` at entry - e.g. 0x1417040F0 / 0x140B76E00
};

enum class Probe : std::uint8_t {
    none = 0,
    /** rcx is the entity-index MANAGER: dump both masks, both tokens, both water marks. */
    manager,
    /** rcx is the manager and the question is only "how many free slots did it see". */
    alloc,
    /** The callee RETURNS the member record gate 2 tests. On leave, log [ret+0x818] -
     *  operand A of `cmp [rdi+0x818], [rsp+0x68]`, the comparison that rejects the peer. */
    member,
    /** Log the 5th-8th STACK arguments on enter. The two predicates feeding the
     *  construction chain (0x1404DF650, 0x1404DF620) are tiny leaves in .pdata gaps and
     *  cannot carry a detour - but their results are passed INTO 0x141703910 as r8d and
     *  the 6th stack arg, so hooking the consumer captures both. */
    stackargs,
    /** rcx OWNS the 31-slot registry: log [rcx+0x170] (count) and the first slots. This
     *  identifies the object 20.224 R6 could not - rbx in 0x1416FF3C0 IS its rcx. */
    registry,
    /** The callee returns an INDEX in eax, or -1 for refused. Log the 32-bit value and
     *  say plainly which it is - the declared width, per the 0x80000001 retraction. */
    retidx,
    /** rcx is the object whose [rcx]+0x6C38 is the PARTICIPANT TABLE. Dump the three
     *  gate bitmasks and, per present participant, the two per-record gate bytes - i.e.
     *  the ENTIRE five-condition construction gate of 20.229, in one place. */
    ptable,
    /** The callee is a PREDICATE: what matters is its return value and WHEN IT FLIPS.
     *  Emitted on leave, and ONLY when the value differs from the last one emitted for
     *  this target - a predicate called 50,000 times yields a handful of lines. */
    retwatch,
    /** The callee is the RESERVATION-TABLE LOOKUP 0x1417C40F0 (20.269 R1): the table base
     *  comes from the obfuscated accessor 0x1417CF0E0, which this probe CALLS (never
     *  detours - the p2-147a class) to walk all 62 x 0x41F0 records and report each
     *  record's two lifecycle states (+0x30E8, +0x1DC0 - the CONNECTION ladder
     *  none/empty/connecting/established/connected, 20.271 R5) plus its 86-byte identity
     *  prefix at +0x3144. Change-gated on the whole-table state fingerprint, so a dwell
     *  emits lines only when a connection state MOVES. This is the read that names which
     *  rung the peer's connection sticks at (the W2 front, 20.271). */
    resvtable,
    /** The callee is a TRACKING-ROW ADDER (20.241 R1): rcx is the pool, rdx points at the
     *  machine-id qword it will append at [pool + i*10 + 0x602BC]. On enter, log the
     *  caller RVA and the machine-id VALUE ([rdx], not rdx - the pointer is not the
     *  identity). The caller RVA separates the genuine feed from the self-heal. */
    trackadd,
    /** The callee is THE POOL DISPATCHER 0x1404F7DF0: rcx is the pool and R8D is the
     *  activity-message TYPE it is about to route through the 21-entry table at
     *  0x141F92360. p2-154 proved a type-45 body is delivered and ACCEPTED at the
     *  message layer (0x140E0F000) while +0x602C4 never moves (20.247), and the table
     *  itself is static and DOES carry 0x2D -> 0x1404F3870 - so the open question is
     *  purely whether the message ever reaches this function with that type. Emits ONE
     *  line per DISTINCT type ever dispatched, so it cannot flood and cannot be starved
     *  by the noisy early types the way three earlier boots' budgets were. */
    pooldisp,
    /** The callee is a POOL MESSAGE HANDLER taking the pool in rcx: dump the whole
     *  machine-id tracking array (count at +0x602B8, then rows of 10 bytes - mid at
     *  +0x602BC, contactable byte at +0x602C4, latch at +0x602C5). Run on ENTER and
     *  LEAVE, so one call shows both that the handler ran and whether it changed
     *  anything. This is what turns "c4 never moved" into "the handler did / did not
     *  run, and did / did not write". */
    poolc4,
    /** The callee is the +0x602C4 READER 0x1404F7680: rcx is the pool and rdx points at
     *  the machine id being asked about. p2-155 logged only its ANSWER (change-gated) and
     *  so could say the answer was always 0 but not WHAT WAS ASKED - the exact gap that
     *  left 20.248 R3 open. Emits one line per DISTINCT (pool, machine id) pair, so the
     *  evaluator's whole query set is captured without flooding a 7,000-call path, and
     *  the change-gated return value is still emitted on leave. */
    c4query,
    /** THE PUBLISH/RESTORE OBSERVER (20.254): rcx = copy-side object (its +0x80 is the
     *  staging or the live table), rdx = image id, r8 = the OTHER side (the table on
     *  publish, the source image on restore). Logs both sides, the role (classified via
     *  gate_wwatch's armed tables), the source's per-record gate bytes, and one-shots a
     *  full source-image hexdump on the first restore. The writer 20.246 could never
     *  see, observed. */
    pubrest,
    /** THE GUARD'S REQUIRED-BIT READER (20.279 R2 / 20.280): rcx = the guard's container;
     *  the bit predicate 1 demands is dword[[rcx+8]+8] + 6 - the value the red team could
     *  only infer (bit 7 mac / 6 rig). Novelty-gated on the bit VALUE, so 898 evaluations
     *  cost a handful of lines and a mid-boot change of the required bit is loud. */
    gatebit,
};

struct Target {
    /** Short tag used in the log line and the census. */
    const char* name;
    /** Image RVA of the function start. */
    std::uintptr_t rva;
    /** Detailed lines this hook may emit before it goes counter-only. */
    unsigned budget;
    /** WHICH REGISTER holds the callee's out-pointer, if any. Read after the original
     *  returns (the callee dereferenced it, so it is proven valid). 20.216 R4: idx_alloc's
     *  rax is the out-pointer round-trip, never the verdict.
     *  THIS WAS A BOOL MEANING "rdx" AND IT FROZE A CLIENT (2026-08-31, p2-145 attempt 1):
     *  memidx_alloc 0x1417040F0 and memidx_pop 0x140B76E00 both write their result through
     *  RCX (`mov dword [rcx],-1` at entry), not rdx. Declared as the bool, the observer
     *  dereferenced rdx - which for memidx_alloc is the KIND ARGUMENT, value 2. Reading
     *  address 0x2 inside a detour hung the client at Tower entry, with `stage=enter
     *  fn=memidx_alloc call=1` as the last line in the log and no matching leave.
     *  The register is per-function and MUST be read off the callee's own prologue. */
    OutParam out_param;
    /** When true, log the first 8 bytes at [rcx] on enter - the callee's rcx is a
     *  message-object pointer whose CONTENT is the question (the activity router's
     *  byte[1] flag gate, FINDINGS 20.217 amendment 3). Read-before-call only; the
     *  router only reads its argument. */
    bool dump_rcx;
    /** Structured field probe to run on enter and leave. See Probe. */
    Probe probe;
    /**
     * When non-zero, log ONLY calls whose caller RVA equals this. Both gate-2 helpers
     * (0x140B39DC0, 0x1412FBA60) are shared utilities called from all over the client -
     * 0x1412FBA60 alone ran 737,556 times in p2-145 and its 8 budgeted lines were spent
     * entirely by unrelated callers, so the creation loop's own calls were never sampled.
     * That is the project's "BUDGET OBSERVERS PER EVENT CLASS" rule, violated by me in an
     * instrument written the same day I wrote the postmortem about it. Filtering by call
     * site makes the budget mean "N samples of THE CALL WE CARE ABOUT".
     */
    std::uintptr_t caller_filter;
    /**
     * FIRST-SEEN-KEY LEAVE GATING (postmortem 09-01, the pattern that worked). The flat
     * budget exhausts in the earliest burst - for ent_gate that is the self-slot join
     * burst - and the informative outcomes (a DIFFERENT slot, a DIFFERENT bail class)
     * land after the cap, which is exactly how p2-164's log went silent through the
     * entire peer era. Past the budget, a target with this flag still emits the leave
     * line the first time each (rdx slot, ret class) pair is seen, so a bail-3 flip or
     * a pass on the peer slot can never be invisible. Bounded by the key table, not by
     * the budget.
     */
    bool first_seen_leave;
};

/**
 * The entity/render path, entry-first. Budgets are PER TARGET, never shared - a shared cap
 * gets spent by the noisiest hook and the resulting null reads as a finding (the rule that
 * cost 20.190/20.193 R5 two boots, and cost p2(133) half its instrument).
 */
// Every traced RVA is declared here in the form RE_scripts/verify_hook_rvas.py matches
// (`constexpr std::uintptr_t k...Rva = 0x...;`) so the gate resolves EVERY ONE against
// .pdata. Putting them only inside the table below would leave them ungated - which is
// precisely the p2(112) trap this tracer exists to avoid repeating.
constexpr std::uintptr_t kEntRecvRva = 0x1718510;
constexpr std::uintptr_t kEntHeaderRva = 0x1717EB0;
constexpr std::uintptr_t kEntCreateRva = 0x1718080;
constexpr std::uintptr_t kQueueEvtRva = 0x16F0F60;
constexpr std::uintptr_t kQueueDownRva = 0xE04E30;
constexpr std::uintptr_t kActRouterRva = 0x16E6ED0;
constexpr std::uintptr_t kSobjDecodeRva = 0xE739D0;
constexpr std::uintptr_t kRingCommitRva = 0xDFEC50;
// The type-20 routing lookup (entity-index-allocation-schema.md FINDING 1/2): the
// handle-table lookup whose SILENT -1 failure drops the whole allocation body
// (type20-consumer-read.md). Calls/failures here measure "decoded vs silently
// dropped" on the emission boot. 0x140C23290, verified against .pdata by the gate.
constexpr std::uintptr_t kIndexLookupRva = 0xC23290;
// The type-21 grant chain (claim K, entity-index-allocation-schema.md): the
// activity-router case-21 HANDLER, the entity-manager CONSUMER that walks the
// donated bitmap, and the FREE-SLOT ALLOCATOR whose -1 exit is the failure.
// p2(142): the grant is accepted at ingress but the failures continue — these
// three split "handler ran?" from "consumer ran?" from "allocator ran?".
constexpr std::uintptr_t kIdxGrantHandlerRva = 0x16F04C0;
constexpr std::uintptr_t kIdxGrantConsumerRva = 0x170CFB0;
constexpr std::uintptr_t kIdxAllocRva = 0x1711D10;
// The entity-index POOL PROTOCOL itself (claims H/K/Q, entity-index-allocation-schema.md):
// the client's own senders, the runtime-registered receiver, and the apply that ORs a
// donated bitmap into the pool mask. p2(143) discriminates three hypotheses: the index
// request goes client->client (DTLS peer channel), it never fires at all, or it rides
// established-plane id 37. The senders log their caller; the receiver's caller names the
// runtime dispatch. 0x1404F2970's .pdata entry is a 29-byte chained FRAGMENT record, but
// the real body continues contiguously to 0x1404F2AC4 (~341 B, disassembly-checked), so
// the detour has room - the p2(137) "too small" rule was about whole functions < 40 B.
constexpr std::uintptr_t kPoolSendRequestRva = 0x4F88C0;
constexpr std::uintptr_t kPoolSendDonateRva = 0x4F56F0;
constexpr std::uintptr_t kPoolReceiveRva = 0x4F2970;
constexpr std::uintptr_t kPoolApplyRva = 0x4F5D60;
// Instrument v3 (type-30 chase): the POOL DISPATCHER 0x1404F7DF0 searches a 21-entry
// type->handler table (0x141F92360) by its r8d argument - logging r8 names EVERY type
// that reaches the pool family live. The ASSIGNMENT handler 0x1404F34C0 decodes the
// type-30 body (schema 0x80808683, one u32) and writes it to [pool+0x602b4], whose -1
// default blocks the manager's post-init local-mask sync (FINDINGS 20.217 amendment 2:
// the type-30 push is accepted at ingress but the host mask stays empty - did the
// handler run?). The sync itself (0x14171BB50) is NOT hooked: its prologue carries a
// rel32 call and the detour's relocation safety is unproven for that shape.
constexpr std::uintptr_t kPoolDispatchRva = 0x4F7DF0;
constexpr std::uintptr_t kPoolAssignRva = 0x4F34C0;
// Instrument v4 (p2-144, THE LIFECYCLE CENSUS). Static reads this session established the
// entity-index lifecycle as ONE orchestrator 0x14171D780(mgr) running three stages:
//     init 0x14171DB20  ->  fill 0x14170ACB0  ->  sync 0x14171BB50 (tail jmp)
// and, decisively, that the ALLOCATOR's mask (mgr+0xC118) is a DIFFERENT object from the
// pool mask (pool+0x5FE98) our join grants fill. The only writer that moves supply into
// the allocator's mask is `fill`, and `fill` is gated on [pool+0x602B0] - a token written
// ONLY by pool dispatch type 0x1C (28), which this fork has never sent. The type-30
// message we do send writes the ADJACENT token [pool+0x602B4], which gates `sync` - an
// OUTBOUND report (0x1404FBAD0 sends {token:4||bitmap:1024}), not a local fill.
// The orchestrator 0x14171D780 itself is NOT hooked: at 35 bytes it is under the 40-byte
// floor that retired registry 0x16BAB50 (36 B) and ent_encode 0x171E240 (37 B). `init` is
// its first call and carries the same rcx, so hooking init loses nothing.
// Prologue safety, checked byte by byte (Detours relocates, but never needs to here):
//   init  0x14171DB20: 11 position-independent bytes before the rip-relative mov at +11
//   fill  0x14170ACB0:  7 position-independent bytes before mov rax,[rcx+8] at +7
//   sync  0x14171BB50:  9 position-independent bytes before the rel32 call at +9
// All three clear the 5 bytes a jmp rel32 needs without touching a relocatable operand.
// Instrument v5 (p2-145, THE CREATION-GATE CENSUS). 20.220 read the peer-creation path
// end to end:
//   loop 0x1413086E0(+0x44A) -> creator 0x1416EE180 -> 0x14170F190 -> idx_alloc 0x141711D10
// and found ONE predicate, 0x1412AADF0, gating ALLOCATION **ON** and CREATION **OFF** -
// mutually exclusive modes, the shape of an authority/role split. 20.219 measured ZERO
// idx_alloc calls with a peer present, which (since idx_alloc sits inside the create)
// means the LOOP NEVER REACHED ITS CREATE STEP. So the question is now the GATES.
// 0x1412AADF0 itself is 37 BYTES - under the 40-byte detour floor that retired registry
// 0x16BAB50 (36 B) and ent_encode 0x171E240 (37 B). It is NOT hooked. Instead its two
// components are, and the predicate is reconstructed as `auth_a() && *auth_b() != 0`:
// that also says WHICH half decides, which hooking the predicate itself could not.
// Both components read obfuscator-encrypted globals, so they are not statically
// resolvable and MUST be measured.
// p2-146: GATE 2, the comparison that rejects the peer. In the loop at 0x1413086E0:
//     0x141308AA4  call 0x140B39DC0        -> rax = rdi = THE MEMBER RECORD
//     0x141308AB1  call 0x1412FBA60(&rsp+0x68) -> writes the value to compare against
//     0x141308ABA  mov rax, [rdi+0x818]
//     0x141308AC1  cmp rax, [rsp+0x68]     ; QWORD compare - equal or the member is SKIPPED
// Two hooks give both operands: member_get's RETURN (+0x818 read on leave) is operand A,
// and gate1's rcx OUT-SLOT is operand B. Both are filtered to the loop's own call site.
constexpr std::uintptr_t kMemberGetRva = 0xB39DC0;      ///< returns the member record
constexpr std::uintptr_t kMemberOwnerField = 0x818;     ///< operand A lives here
constexpr std::uintptr_t kMemberGetCaller = 0x1308AA9;  ///< return addr of the loop's call
constexpr std::uintptr_t kGate1LoopCaller = 0x1308AB6;  ///< return addr of the loop's call
// p2-147: THE ENTITY-RECEIVE CONSTRUCTION CHAIN (20.224/20.225). The receiver object for
// ent_recv does not exist in a live two-player Tower session - zero instances of any of its
// four secondary vtables across 6.49 GB of dump. The chain that would build it is now named
// end to end and is CALL-ONLY (verified under BOTH encodings after negative_audit.py flagged
// the 20.209 R2 class):
//   0x141709836/83 (entity-manager update, 35,030 calls/boot - measured)
//     -> 0x141702580 (21 B: construct at +0x1A8, teardown at +0x153)
//       -> 0x141703910 -> 0x1416FF3C0 -> 0x1416CA0B0 -> ctor 0x1416BB1E0
// This boot asks ONE binary question: which link is the last one reached, and does
// get-or-create return an index or -1.
// NOT HOOKED, and neither is needed: 0x141702580 is 21 B (under the 40-B floor that retired
// registry 0x16BAB50 / ent_encode 0x171E240) - ent_gate's call count covers it; the ctor
// 0x1416BB1E0 sits in a .pdata GAP so verify_hook_rvas.py would reject it - ent_alloc's
// RETURN VALUE covers it; predicates 0x1404DF650 / 0x1404DF620 are gap leaves - ent_gate's
// stackargs probe captures their results as they are passed in.
// p2-148: THE GATE'S INPUTS. 20.229 resolved the construction gate to named fields but
// could not locate them live - three search anchors all died on tool limits. The route in
// is 0x141702580's own argument: its 21-byte head does `mov r15,rcx; mov rcx,[rcx]`, and
// the body then calls 0x1404F5800 (= `lea rax,[rcx+0x6C30]; ret`) and takes rax+8. So
//     participant table = [rcx] + 0x6C38
// with rcx the argument. 0x1417021C0 is called with the IDENTICAL rcx immediately before
// 0x141702580 (both `lea rcx,[rbx+0x30]` at 0x14170982D/0x141709832), is a proper .pdata
// entry of 44 B, has 11 position-independent prologue bytes and zero mid-detour branches.
// So the standard rcx capture suffices - no callee-saved register capture, no naked stub,
// no inline asm, none of the launch-kill risk that carried.
// NOT hooked: 0x141702595 (the 534-B body). It is entered by FALL-THROUGH from the 21-byte
// head, not by a call - a detour there would `ret` into the head's frame. Checked, excluded.
constexpr std::uintptr_t kPTableRva = 0x17021C0;      ///< same rcx as 0x141702580
// p2-159: the publish/restore entry (20.254) - the only clean caller of the bulk copier
// 0x1404DF6A0 that refreshes the participant table. Verified .pdata start
// 0x1403CB340..0x1403CB3EF; the boot gate resolves it like every RVA here.
constexpr std::uintptr_t kPubRestRva = 0x3CB340;constexpr std::uintptr_t kTableFromObj = 0x6C38;      ///< [rcx] + this = participant table
constexpr std::uintptr_t kMaskA = 0x59248;            ///< gate cond 3: bit i must be SET
constexpr std::uintptr_t kMaskB = 0x5924C;            ///< gate cond 1: first set bit = i
constexpr std::uintptr_t kMaskC = 0x59250;            ///< the third mask (0x1404DF650)
constexpr std::uintptr_t kRecStride = 0x2AC0;         ///< per-participant record stride
constexpr std::uintptr_t kRecGateByte = 0x38;         ///< cond 5: bit 4 of this must be SET
constexpr unsigned kMaxParticipants = 32;
constexpr std::uintptr_t kEntGateRva = 0x1703910;      ///< chain top; carries both predicates
constexpr std::uintptr_t kResvLookupRva = 0x17C40F0;   ///< the reservation-table LOOKUP
                                                       ///< (20.269 R1); also the reserve
                                                       ///< path's own lookup, so it runs
                                                       ///< without the poke. Its probe
                                                       ///< walks the table states.
constexpr std::uintptr_t kConnMgrRva = 0x17C53B0;      ///< the connection-state ITERATOR
                                                       ///< (20.273 R2): walks the
                                                       ///< reservation records' two
                                                       ///< state fields on the manager
                                                       ///< object and notifies. Its
                                                       ///< CALLER names what drives each
                                                       ///< evaluation (W2's question).
constexpr std::uintptr_t kResvNotifyRva = 0x17FFA20;   ///< the per-record NOTIFIER the
                                                       ///< iterator calls (ecx=idx, dl,
                                                       ///< r8d, r9d - the standard enter
                                                       ///< capture IS the args). Body is
                                                       ///< obfuscated (keyed family) but
                                                       ///< the prologue is clean 5-byte
                                                       ///< stores; WIDE-NET per the
                                                       ///< user's directive, with the
                                                       ///< p2-147a attach-crash risk
                                                       ///< PRE-NAMED as outcome (e2).
constexpr std::uintptr_t kEntPassRva = 0x17039CD;      ///< the guard's fall-through body (W1):
                                                       ///< entered ONLY when all three bails
                                                       ///< pass, by fall-through or nothing
                                                       ///< (zero E8 callers - 20.269 R1).
                                                       ///< calls>0 here IS outcome (b).
constexpr std::uintptr_t kEntRegRva = 0x16FF3C0;       ///< bail-on-(-1), then register
constexpr std::uintptr_t kEntAllocRva = 0x16CA0B0;     ///< get-or-create: eax = index or -1
constexpr std::uintptr_t kEntTeardownRva = 0x16CACD0;  ///< the destroy half
constexpr std::uintptr_t kEntConfigRva = 0x16EBD30;    ///< configure, takes the kind flag
constexpr std::uintptr_t kEntPostRva = 0x16E8200;      ///< runs after registration
/** Registry fields on 0x1416FF3C0's rcx: count, then 31 pointer slots. */
constexpr std::uintptr_t kRegistryCount = 0x170;
constexpr std::uintptr_t kRegistrySlots = 0x178;
constexpr std::uintptr_t kCreateLoopRva = 0x13086E0;   ///< the peer-creation loop
constexpr std::uintptr_t kPbCreateRva = 0x16EE180;     ///< creator; args (out,kind,index,flags)
constexpr std::uintptr_t kEntMakeRva = 0x170F190;      ///< calls idx_alloc at +0x3E
constexpr std::uintptr_t kAuthARva = 0x12ABCA0;        ///< predicate half A
constexpr std::uintptr_t kAuthBRva = 0x12AEE50;        ///< predicate half B (deref != 0)
constexpr std::uintptr_t kMemIdxAllocRva = 0x17040F0;  ///< per-member index wrapper
constexpr std::uintptr_t kMemIdxPopRva = 0xB76E00;     ///< per-member index free-list
constexpr std::uintptr_t kLoopGate1Rva = 0x12FBA60;    ///< the loop's first gate
constexpr std::uintptr_t kIdxPublishRva = 0x1704870;   ///< runs right after [rbx+8] is set
constexpr std::uintptr_t kMgrInitRva = 0x171DB20;
constexpr std::uintptr_t kMgrFillRva = 0x170ACB0;
constexpr std::uintptr_t kMgrSyncRva = 0x171BB50;

// p2-152: THE TRACKING-ROW ADDERS (20.240/20.241). The +0x602BC tracking array is the
// feed the fork never delivers: "Could not find tracking data for peer" is the client's
// own verdict even on endpoint-bearing rows (20.240 R3), and the client never ACKs, so
// the retry cap withdraws the peer after 2 bodies. The static hunt (20.241 R5) closed
// with "REACHED, not named" - the genuine feed arrives through a registration-table
// callback from flattened second-.text, so the DISPATCHING type cannot be named
// statically. The dynamic discriminator is one boot: which caller RVA drives an add,
// and for WHICH machine-id.
//
// The canonical adder 0x1404F4980 writes the machine-id qword at
// [pool + i*10 + 0x602BC], zeroes the flag bytes at +0x602C4/+0x602C5, and increments
// the count at +0x602B8. It sits in a .pdata GAP (nearest entry 0x1404F4830..0x1404F4975
// ends at a `ret` at 0x1404F4974; the 5 bytes after it jmp away at 0x1404F497B, so the
// adder is NOT entered by fall-through - the caller set is exactly its three rel32 call
// sites, 20.241 R2). verify_hook_rvas.py flags it NOT-CODE by construction - this is the
// DOCUMENTED EXCEPTION, carried here because the usual gate's protection (a .pdata
// function START) is exactly what this address lacks. In its place, verified by hand:
//   - 66 B total (0x1404F4980..0x1404F49C2, single `ret`) - over the 40-B floor;
//   - 11 position-independent lead bytes; the first instruction's displacement is
//     ABSOLUTE ([rcx+0x602b8]), not RIP-relative, so the Detours relocation is trivial;
//   - prologue safety byte-checked: 7 B movsxd + 4 B lea + 3 B mov before the 8 B
//     rip-relative store at +0xE;
//   - NO branch in either .text lands inside the overwritten first 5 bytes
//     (RE_output/claims/probe_mid_detour_0x1404f4980_20260831.py, both .text sections,
//     E8/E9/0F 8x/EB all checked - CLEAN for this entry and for 0x1404F7710).
// Hooking the three CALL SITES instead was rejected: a mid-function detour is a new,
// riskier instrument shape for the same information - the return address at this entry
// IS the call site (+5), so one hook discriminates all three.
// The fixup variant 0x1404F7710 (85 B, PROPER .pdata fn) is hooked beside it: the
// self-heal's adds must be separable from the genuine feed's, and the retail fixup
// lines (site 194/195) only timestamp, they do not name the machine-id.
constexpr std::uintptr_t kTrackAddRva = 0x4F4980;    ///< canonical adder (see above)
constexpr std::uintptr_t kTrackFixupRva = 0x4F7710;  ///< fixup variant, proper .pdata

// p2-153: THE LATCH SETTER + THE +0x602C4 READER (20.243 R3/R4 + 20.244). The
// release predicate is the peer row's +0x602C5 latch byte; the chain is validated
// by femu (20.244 R2, all 7 PASS). What is UNMEASURED is WHICH path sets the
// latch (or the +0x602C4 "contactable" byte) live:
//   0x1404FC2E0 (90 B, .pdata fn) - find-by-mid then mov byte [..+0x602C5], r8b.
//     Its three callers all pass r8b=1: 0x140C1846D (post-release self-set),
//     0x140C174A5 (the per-tick evaluator's activation block, requires entry
//     state dword == 0xA), 0x140C17D02 (the wire-record path, machine id at
//     record+0xD). Hooking IT names the path by caller_rva - the same
//     return-address discrimination that worked for the adder.
//   0x1404F7680 (105 B, .pdata fn) - find-by-mid, returns movzx of the FOUND
//     row's +0x602C4 (the byte the evaluator checks BEFORE it will write
//     [rbx+4]=5 + latch; BOTH insert families zero it and no setter is known).
//     retwatch on it logs every +0x602C4 TRANSITION - if it ever reads nonzero
//     for the peer, the evaluator can activate; if it never does, the fork-side
//     lever narrows to making +0x602C4 nonzero.
// Both entries: exactly-5-byte openings (mov [rsp+8],rbx / mov [rsp+8],rbx) -
// the same single-instruction displacement class as kTrackFixupRva, verified
// safe (Detours relocates the 5-byte store wholesale; no RIP-relative operand).
// Mid-detour scan (entry+1..entry+10, E8/E9/0F 8x/EB, both .text) CLEAN for
// both; xref_scan --ptrs: no data-slot references into either window.
constexpr std::uintptr_t kTrackSetRva = 0x4FC2E0;    ///< latch setter (all callers r8b=1)
constexpr std::uintptr_t kTrackC4Rva = 0x4F7680;     ///< +0x602C4 reader (retwatch)

// p2-155: WHERE THE TYPE-45 BODY DIES (20.247 R6). p2-154 shipped the contactable
// push; the body reached both clients (`type=45 result=ok accepted=1`) AFTER the peer's
// tracking row existed, and +0x602C4 never moved on either machine. Static work this
// session then removed two of the three candidate explanations:
//   - the 21-entry pool dispatch table at 0x141F92360 DOES map 0x2D -> 0x1404F3870
//     (entry 16, pointer slot 0x141F92468) - so the routing TABLE is not the gap;
//   - 0x1404F7DF0 has NO rel32 callers; its address lives in one .rdata slot
//     (0x141BEA568, a pool/activity-client vtable) - it is invoked indirectly, which is
//     the same runtime-registration shape as 20.241 R4.
// So the question is exactly: does the message reach 0x1404F7DF0 carrying type 45?
// TYPE 30 IS THE POSITIVE CONTROL and it is the point of this instrument: the fork's
// type-30 push is the one pool body known to land (p2-144), so if pool_disp logs 30 and
// never 45, the answer is upstream routing; if it logs NEITHER, then our whole model of
// how type 30 reaches the pool is wrong and p2-144's reading needs revisiting. Without
// that control a silent hook and a silent client are the same observation (L13).
// Detour safety, verified this session for all three: each is an exact .pdata function
// START; the relocated prologue is 6/11/6 bytes of whole instructions with NO
// RIP-relative operand; and a both-.text scan for E8/E9/EB/0F8x landing in entry+1..+10
// found nothing for any of them.
constexpr std::uintptr_t kPoolDispRva = 0x4F7DF0;    ///< pool dispatcher (type in r8d)
constexpr std::uintptr_t kT45HandlerRva = 0x4F3870;  ///< type-45 handler (sets +0x602C4)
constexpr std::uintptr_t kT30HandlerRva = 0x4F34C0;  ///< type-30 handler - POSITIVE CONTROL

/**
 * Entity-index MANAGER field offsets (verified-by-reading, this session).
 * The 6-byte per-slot record table (8192 x 6 = 0xC000 B) ends exactly at the mask.
 */
constexpr std::uintptr_t kMgrFreeMask = 0xC118;   ///< 8192-bit free-slot mask (1 = FREE)
constexpr std::uintptr_t kMgrWaterLow = 0xC518;   ///< request below this popcount
constexpr std::uintptr_t kMgrWaterHigh = 0xC51C;  ///< donate above this popcount
constexpr std::uintptr_t kMgrSubObject = 0x8;     ///< [mgr+8]; its +0x10 is the pool

/** Entity-index POOL field offsets (verified-by-reading, this session). */
constexpr std::uintptr_t kPoolFromSub = 0x10;     ///< pool = [[mgr+8]+0x10]
constexpr std::uintptr_t kPoolFreeMask = 0x5FE98; ///< the mask our join grants OR into
constexpr std::uintptr_t kPoolSentFlag = 0x60299; ///< non-zero = init branch B exits
constexpr std::uintptr_t kPoolFillToken = 0x602B0;///< gates `fill`  - set by TYPE 28
constexpr std::uintptr_t kPoolSyncToken = 0x602B4;///< gates `sync`  - set by TYPE 30

/** The 1024-byte masks both carry 8192 bits. */
constexpr std::size_t kMaskBytes = 0x400;

// Schema-key descriptor POINTERS, read from the two handlers' own rip-relative loads
// (0x1404F3481 -> 0x141FA42A8 for type 28; 0x1404F3591 -> 0x141FA42B8 for type 30).
// Each global holds a POINTER to a descriptor whose FIRST DWORD is the key the decoder
// 0x1404DC080 is called with. Both descriptors live past .data's raw-backed extent, so
// they are zero on disk and only exist at runtime - which is the whole reason this boot
// has to fetch them. Deliberately NOT named k...Rva: they are data, not hook targets,
// and the verify_hook_rvas.py gate should not list them for code review.
constexpr std::uintptr_t kType28SchemaKeyPtr = 0x1FA42A8;
constexpr std::uintptr_t kType30SchemaKeyPtr = 0x1FA42B8;
/** The type-30 key is independently known; it is this instrument's self-test. */
constexpr std::uint32_t kType30SchemaKeyOracle = 0x80808683;

constexpr std::size_t kTargetsSize = 46;
constexpr std::array<Target, kTargetsSize> kTargets{{
    // The entity receive cluster. 0x141718510 is the ENTRY and has ZERO static references
    // of any kind in the whole image (20.209) - its caller is the open question, so it gets
    // the largest budget.
    {"ent_recv",    kEntRecvRva, 24},
    {"ent_header",  kEntHeaderRva, 12},
    {"ent_create",  kEntCreateRva, 12},
    // Our own carrier and where it goes. p2(136) proved the record is accepted here and
    // creates nothing; these two show exactly where it dead-ends.
    {"queue_evt",   kQueueEvtRva, 8},
    {"queue_down",  kQueueDownRva,  8},
    // The activity-message ROUTER: fires for every svc-9 message and names the type, so
    // this is the census that tells us which carriers exist at all.
    {"act_router",  kActRouterRva, 32, OutParam::none, true, Probe::none},
    // The 0x89 sobject record decoder and the event-ring commit the queue path ends in.
    {"sobj_decode", kSobjDecodeRva,  8},
    {"ring_commit", kRingCommitRva,  8},
    // The type-20 routing lookup: fires per allocation notification; a null return
    // (logged via ret=0) means the body was routed to nothing and dropped silently.
    {"index_lookup", kIndexLookupRva, 12},
    // The type-21 grant chain: the router's case-21 HANDLER (does the accepted
    // body reach the case at all), the entity-manager CONSUMER that walks the
    // donated bitmap (enter rcx = the manager, rdx = the body — its enter/leave
    // registers name the object family live), and the ALLOCATOR (its enter rcx
    // must be the same manager; its -1 exits are the failure).
    {"idx21_handler",  kIdxGrantHandlerRva, 12, OutParam::none},
    {"idx21_consumer", kIdxGrantConsumerRva, 12, OutParam::none},
    {"idx_alloc",      kIdxAllocRva, 12, OutParam::rdx, false, Probe::alloc},
    // The pool protocol (p2-143): send_request fires at most once per entity-manager
    // init (sent-flag gates it), send_donate is a client-host donation, pool_recv is
    // the runtime-registered schema decode of an inbound donation, pool_apply ORs it
    // into the mask. ALL FOUR may read zero - that is the "request never fires"
    // outcome, which is itself the discriminator (see the p2-143 boot brief).
    {"pool_send_req",  kPoolSendRequestRva, 16},
    {"pool_send_don",  kPoolSendDonateRva, 16},
    {"pool_recv",      kPoolReceiveRva, 16},
    {"pool_apply",     kPoolApplyRva, 16},
    // Instrument v3 (type-30 chase): pool_dispatch's enter r8 = the pool-message
    // type, so its census names every type the family receives; pool_assign firing
    // = the type-30 body decoded and [pool+0x602b4] written (its -1 default is the
    // host client's wall). The sync 0x14171BB50 stays unhooked (rel32-call prologue).
    {"pool_dispatch",  kPoolDispatchRva, 24},
    {"pool_assign",    kPoolAssignRva, 16},
    // Instrument v4 (p2-144): the entity-index LIFECYCLE. These three are the whole
    // point of the boot and each carries the manager probe, so every gate on the chain
    // reports its own inputs rather than being inferred from a downstream silence.
    //   mgr_init : which branch ran (A = memset all-free, B = donate/request), and the
    //              water marks + both popcounts that decide it.
    //   mgr_fill : THE instrument entity-index-allocation-schema.md line 418 asked for
    //              and nobody built. Its gate value [pool+0x602B0] at enter is the
    //              boot's primary claim; its mask delta enter->leave is the proof.
    //   mgr_sync : closes the "the one-shot sync runs" assumption STATE currently
    //              asserts with no measurement behind it.
    {"mgr_init",       kMgrInitRva, 16, OutParam::none, false, Probe::manager},
    {"mgr_fill",       kMgrFillRva, 16, OutParam::none, false, Probe::manager},
    {"mgr_sync",       kMgrSyncRva, 16, OutParam::none, false, Probe::manager},
    // p2-147: the construction chain. Read top-down; the LAST one with calls>0 is the answer.
    {"ptable",        kPTableRva, 12, OutParam::none, false, Probe::ptable},
    {"ent_gate",      kEntGateRva, 24, OutParam::none, false, Probe::gatebit, 0, true},
    // W2 (20.271 R5): the connection-ladder reader. Emits one line per whole-table state
    // CHANGE: every reservation record's two lifecycle states + identity prefix. Zero
    // writes into game memory; the accessor 0x1417CF0E0 is CALLED, not detoured.
    {"resv",          kResvLookupRva, 32, OutParam::none, false, Probe::resvtable},
    // W2 (20.273): the connection-state iterator. Enter lines carry caller_rva - WHICH
    // subsystem drove each evaluation. Budget 24; the args are context (manager + flags).
    {"connmgr",       kConnMgrRva, 24, OutParam::none, false, Probe::none, 0, true},
    // WIDE NET (user directive): the notifier's args are the promotion's parameters.
    // Attach-crash risk pre-named (p2-147a class) - outcome (e2) of the brief.
    {"notifier",      kResvNotifyRva, 24, OutParam::none, false, Probe::none},
    // W1 (20.269 R5): the fall-through body. Entered by FALL-THROUGH from ent_gate only,
    // never by call, so its enter-line rcx/rdx/r8/r9 are REGISTER RESIDUE, not arguments,
    // and caller_rva is the fall-through frame's stack word - read neither. The COUNT and
    // its timing against the gate poke is the measurement: 0 in every boot so far, and
    // rising with the peer participation staged is outcome (b) of the pre-named tree.
    {"ent_pass",      kEntPassRva, 24, OutParam::none, false, Probe::none, 0, true},
    {"ent_reg",       kEntRegRva, 24, OutParam::none, false, Probe::registry},
    // ent_alloc 0x1416CA0B0 is ALSO REMOVED for p2-147a. It is the one target of the six
    // sitting in comparison-tree obfuscated code (cmp ecx,<random imm32>/je dispatch,
    // VMP-adjacent), and the p2-147 evidence points at the detour's PRESENCE rather than
    // any hook body: all six were attached=1, none ever emitted an enter line across 68 s
    // on a path that runs ~35,000x per boot, and no mid-detour branch exists into any of
    // their first 5 bytes. Hooking obfuscated code is the remaining explanation.
    // NOT A LOSS OF THE ANSWER: ent_reg's registry probe fires on enter AND leave, and the
    // only path from ent_reg to registration runs past 0x1416FF3C0's -1 bail. Count does
    // not rise => allocation REFUSED (outcome a). Count rises => construction SUCCEEDED
    // (outcome d). The binary question is still answered, from the clean-code side.
    // p2-147a: ent_config 0x1416EBD30, ent_post 0x1416E8200 and ent_teardown 0x1416CACD0
    // are REMOVED after p2-147 killed the client at character select three times running.
    // Evidence: all 37 detours attached, no mid-detour branch exists into any of their first
    // 5 bytes (checked), and no new hook emitted an enter line - but the last census was
    // t=60227 against a crash at t=68073, so a 7.8 s blind window plus a buffered-log tail
    // means "no hook fired" is NOT proven. What IS suggestive is context: character select is
    // a world transition, i.e. teardown-heavy, and 0x1416CACD0 is the DESTRUCTOR half.
    // Dropping the three costs outcome (b) - "built then destroyed" can no longer be told
    // from "never built" in one run - and that is stated in the brief rather than hidden.
    // The three CORE targets below still answer the boot's binary question.
    // Instrument v5 (p2-145): THE CREATION GATES. This is the whole boot.
    //   create_loop  - does the loop run at all while a peer is present?
    //   gate1        - its first gate; retwatch, because it is the loop's own filter
    //   auth_a/auth_b- the two halves of the predicate that gates allocation ON and
    //                  creation OFF. retwatch: we want the VALUE and WHEN IT FLIPS, and
    //                  the pair tells us which half decides. Compare mac vs rig: if they
    //                  differ, the authority split is confirmed and NAMED.
    //   memidx_alloc/pop - the PER-MEMBER index ([rbx+8]) allocator, never yet observed.
    //   idx_publish  - fires immediately after [rbx+8] is written; its args carry the
    //                  member and the index that was just assigned.
    //   pb_create    - the creator. enter args ARE the deliverable: rdx=kind, r8=index,
    //                  r9=flags, and leave ret says whether it made anything.
    //   ent_make     - the create that calls idx_alloc; brackets the allocation.
    {"create_loop",   kCreateLoopRva, 24},
    // gate1 now reports its OUT SLOT (operand B of gate 2) and is filtered to the loop's
    // own call site, so its budget buys 24 samples of THE comparison instead of 8 samples
    // of unrelated callers - the "budget observers per event class" rule, re-applied.
    {"gate1",         kLoopGate1Rva, 24, OutParam::rcx, false, Probe::retwatch, kGate1LoopCaller},
    {"member_get",    kMemberGetRva, 24, OutParam::none, false, Probe::member, kMemberGetCaller},
    {"auth_a",        kAuthARva, 4, OutParam::none, false, Probe::retwatch},
    {"auth_b",        kAuthBRva, 4, OutParam::none, false, Probe::retwatch},
    {"memidx_alloc",  kMemIdxAllocRva, 24, OutParam::rcx},
    {"memidx_pop",    kMemIdxPopRva, 24, OutParam::rcx},
    {"idx_publish",   kIdxPublishRva, 24},
    {"pb_create",     kPbCreateRva, 32},
    {"ent_make",      kEntMakeRva, 32},
    // p2-152: THE TRACKING-ROW ADDERS (20.241 R5's dynamic discriminator). The question
    // is WHICH FEED adds a row, for WHICH machine-id. kTrackAddRva is deliberately NOT
    // a .pdata function start - the documented exception above carries the verification
    // that replaces the gate's check. Both probes are change-gated (a (caller, mid, pool)
    // pair already emitted stays silent) AND capped (kTrackProbeCap), so a per-tick
    // alternation between the three call sites cannot storm the log.
    {"track_add",     kTrackAddRva,   16, OutParam::none, false, Probe::trackadd},
    {"track_fixup",   kTrackFixupRva, 16, OutParam::none, false, Probe::trackadd},
    // p2-153: the latch setter (enter probe = same shape as the adders: rcx=pool,
    // rdx=&machine-id; every caller passes r8b=1, verified off all three call sites)
    // and the +0x602C4 reader (retwatch: every transition of the "contactable"
    // byte, change-gated so the per-tick evaluator's 32 calls/tick cost ~0 lines).
    {"track_set",     kTrackSetRva,   16, OutParam::none, false, Probe::trackadd},
    {"track_c4",      kTrackC4Rva,    12, OutParam::none, false, Probe::c4query},
    // p2-155. pool_disp's budget is irrelevant (its probe self-limits to one line per
    // distinct type); the two handlers are cold and get small budgets.
    {"pool_disp",     kPoolDispRva,    0, OutParam::none, false, Probe::pooldisp},
    {"t45_handler",   kT45HandlerRva,  8, OutParam::none, false, Probe::poolc4},
    {"t30_handler",   kT30HandlerRva,  4, OutParam::none, false, Probe::poolc4},
    // p2-159: THE PUBLISH/RESTORE OBSERVER (20.254). The ONLY clean entry to the bulk
    // copier 0x1404DF6A0 that refreshes the participant table (gate bytes included) -
    // the writer 20.246's store-encoding scans could never see. Clean .pdata function
    // (~0xAF bytes). Logs both copy sides, the role (publish vs restore, classified via
    // gate_wwatch's armed tables), the SOURCE image's per-record gate bytes, and on the
    // first restore a one-shot hexdump of the whole source image.
    {"pubrest",       kPubRestRva,     0, OutParam::none, false, Probe::pubrest},
    // DELIBERATELY NOT TRACED: registry 0x16BAB50 (36 B) and ent_encode 0x171E240 (37 B)
    // are too small to carry a detour safely, and schema_res 0x4C74D0 / ent_index 0x4C16C0
    // are hot content-load helpers that run thousands of times before any entity exists.
    // p2(137)'s first build traced all four and the client died before character select.
}};

/**
 * Calls between census reprints. The census is driven from INSIDE the hooks rather than
 * from a background thread: a foreign thread calling the game's logger is an unvalidated
 * risk, and it is not needed - the INSTALL census already prints attached=0/1 for every
 * target, so "installed and never called" is distinguishable from "never hooked" even if
 * not one hook ever fires.
 */
constexpr std::uint64_t kCensusInterval = 64;

/** Wall-clock floor between censuses. See the census call site for why this exists. */
constexpr std::uint64_t kCensusMinIntervalMs = 15000;

/**
 * VERIFIED PASS-THROUGH DEPTH: 4 registers + 16 stack slots, forwarded bit-exact - the
 * same shape profile_harvest uses and the same reason. p2(137)'s first build declared a
 * FOUR-argument trampoline; every traced function that takes stack arguments then had its
 * frame truncated, and the client died before character select. A pass-through hook must
 * forward at least as many slots as the widest callee it wraps.
 */
using AnyFn = std::uint64_t(__fastcall*)(void*, void*, void*, void*,
                                         void*, void*, void*, void*, void*, void*,
                                         void*, void*, void*, void*, void*, void*,
                                         void*, void*, void*, void*) noexcept;

std::array<hooking::detour::Handle, kTargets.size()> g_handles{};
std::array<std::atomic<std::uint64_t>, kTargets.size()> g_calls{};
std::array<std::atomic<unsigned>, kTargets.size()> g_logged{};
/**
 * Last value a structured probe actually emitted, per target, plus a "have emitted"
 * flag. Probes fire ONLY when this changes. p2-144 shipped its probes unbudgeted on the
 * reasoning that the lifecycle was a cold path; it runs 38,596x per boot and produced a
 * ~50MB log (FINDINGS 20.219 R7). Sampling by CHANGE rather than by count keeps every
 * transition - which is the whole signal - while collapsing the steady state to one line.
 */
std::array<std::atomic<std::uint64_t>, kTargets.size() + 1> g_lastProbe{};
std::array<std::atomic<bool>, kTargets.size() + 1> g_hasProbe{};
/** One spare novelty slot beyond the target list: the ptable probe's identity-card
 *  fingerprint gate (the cards change without the masks changing). */
constexpr std::size_t kCardGateSlot = kTargets.size();
/**
 * The tracking-adder probe's per-target emission cap (p2-152). The canonical adder is
 * append-only in retail (count++ on every call), so it cannot be per-tick hot - but the
 * fixup variant runs a find-or-append on every fixup pass, and an alternating
 * (caller, mid) fingerprint would emit on every alternation. A cap bounds the worst case
 * without gating the probe behind the detail budget, which is how three earlier boots
 * lost their answer to noise-spent budgets.
 */
constexpr unsigned kTrackProbeCap = 240;
std::array<std::atomic<unsigned>, kTargets.size()> g_trackEmits{};
/**
 * Source-image dumps per boot (pubrest). TWO shots, not one (p2-160).
 *
 * The one-shot version fired on the FIRST restore, and restores run from the moment the
 * client joins - long before any peer does. It therefore captured a SOLO-state image every
 * time and could never have captured the state the front actually asks about. That is the
 * 09-01 postmortem's failure exactly: a probe that logs the answer and not the question.
 *
 * Shot 0 is the solo baseline (first restore, whatever its shape). Shot 1 is the first
 * restore whose source image carries a GENUINE peer in record 1. The DIFF of the two is
 * the body-to-image byte map the femu lane (20.257) was blocked trying to emulate, and it
 * reads directly whether anything a peer row carries lands at +0x38.
 */
std::atomic<unsigned> g_pubrestDumped{0};
/** Shot 1: set once the peer-bearing source image has been dumped. */
std::atomic<unsigned> g_pubrestPeerDumped{0};
/**
 * The LOCAL identity, learned from the solo baseline's record 0, and the anchor the peer
 * shot is gated on.
 *
 * MEASURED (p2-160 attempt 2): `rec8_1 != rec8_0` is NOT a peer test. The hook saw
 * rec8_0 = 0x1A82CB013E294F94 with rec8_1 = 0x88CB5281391A82CB - record 1 holding the LOCAL
 * identity and record 0 holding a byte-shifted view of it (note 1A82CB is a substring of the
 * local key's low half). It passed the != test, it passed the two-observation stability gate
 * because it is stable and repeatable rather than a one-off tear, and it consumed the peer
 * shot BEFORE the second machine had even joined. attempt 1's pgate had already shown the
 * same shape from the other side: `i=1 self=1`, the local player sitting in slot 1.
 *
 * So the peer shot now requires the image to be ANCHORED: record 0 must equal the identity
 * the solo baseline recorded, and record 1 must be a different populated identity. A shifted
 * or re-ordered view fails the anchor instead of consuming the shot.
 */
std::atomic<std::uint64_t> g_pubrestLocalIdentity{0};
/** Per-phase novelty state for pubrest (enter and leave tracked independently). */
std::array<std::atomic<std::uint64_t>, kTargets.size()> g_pubrestLastEnter{};
std::array<std::atomic<std::uint64_t>, kTargets.size()> g_pubrestLastLeave{};
std::array<std::atomic<bool>, kTargets.size()> g_pubrestSeen{};
std::atomic<bool> g_installed{};
std::atomic<std::uint64_t> g_total{};
std::atomic<std::uint64_t> g_lastCensusMs{};
std::uintptr_t g_base{};

void emit(const char* text, std::size_t length) noexcept {
    core::log::write(core::log::Channel::client, core::log::Level::info, {text, length});
}

/** Prints every target's call count, zeros included. Defined below; used by the observer. */
void emit_summary(const char* reason) noexcept;

/** Counts set bits without assuming POPCNT: 128 words, cold path, correctness over speed. */
[[nodiscard]] unsigned mask_popcount(const void* mask) noexcept {
    if (mask == nullptr) {
        return 0U;
    }
    const auto* words = static_cast<const std::uint64_t*>(mask);
    unsigned bits = 0U;
    for (std::size_t index = 0; index < kMaskBytes / sizeof(std::uint64_t); ++index) {
        std::uint64_t word = words[index];
        while (word != 0U) {
            word &= word - 1U;
            ++bits;
        }
    }
    return bits;
}

/**
 * THE GUARD'S REQUIRED-BIT READER. The guard 0x141703910 computes
 * bit = dword[[rcx+8]+8] + 6 and every reservation lookup on this path filters records by
 * that bit in the record's mask word. Which bit runs live is the difference between
 * "the peer's record is selectable" and "no record can ever match" (20.279: the red team
 * derived 7 on the mac / 6 on the rig from the logged bail-5s; this pins it at runtime).
 * Emitted on CHANGE only; the read chain dereferences exactly what the guard itself
 * dereferences on every call, SEH-guarded besides.
 */
[[nodiscard]] bool probe_changed(std::size_t index, std::uint64_t value) noexcept;
[[nodiscard]] const void* at(const void* base, std::uintptr_t offset) noexcept;
void emit_gatebit(std::size_t index, const char* fn, std::uint64_t call,
                  const void* rcx) noexcept {
    if (rcx == nullptr) {
        return;
    }
    const void* const containerA = *static_cast<const void* const*>(at(rcx, 8));
    if (containerA == nullptr) {
        return;
    }
    const std::uint32_t containerValue =
        *static_cast<const std::uint32_t*>(at(containerA, 8));
    const std::uint64_t bit =
        static_cast<std::uint64_t>(static_cast<std::int32_t>(containerValue) + 6);
    if (!probe_changed(index, bit)) {
        return;
    }
    std::array<char, 224> t{};
    const int w = std::snprintf(t.data(), t.size(),
        "ev=mtrace stage=gatebit fn=%s call=%llu container=0x%llX value=%d bitreq=%llu",
        fn, static_cast<unsigned long long>(call),
        reinterpret_cast<unsigned long long>(containerA),
        static_cast<int>(containerValue),
        static_cast<unsigned long long>(bit));
    if (w > 0) { emit(t.data(), static_cast<std::size_t>(w)); }
}

/**
 * True when `value` differs from the last value this target emitted (always true the
 * first time). Cheap, lock-free, and deliberately racy: a duplicate line under a race is
 * harmless, a missed transition is not, so the compare-then-store is not made atomic.
 */
[[nodiscard]] bool probe_changed(std::size_t index, std::uint64_t value) noexcept {
    const bool seen = g_hasProbe[index].load(std::memory_order_relaxed);
    if (seen && g_lastProbe[index].load(std::memory_order_relaxed) == value) {
        return false;
    }
    g_lastProbe[index].store(value, std::memory_order_relaxed);
    g_hasProbe[index].store(true, std::memory_order_relaxed);
    return true;
}

/** Byte-offset helper so the field arithmetic below reads like the offset table. */
[[nodiscard]] const void* at(const void* base, std::uintptr_t offset) noexcept {
    return static_cast<const std::byte*>(base) + offset;
}

/**
 * FIRST-SEEN-KEY STATE: one small open-addressing table per target. A leave line past the
 * budget is emitted exactly once per (slot, ret-class) key - the informative transition
 * (bail 5 -> bail 3, or the first peer-slot evaluation) is a NEW key and can never be
 * silenced by an exhausted budget. 16 keys is generous: the real key space is the
 * participant slot count times four ret classes.
 */
constexpr std::size_t kFirstSeenKeys = 16;
std::atomic<std::uint64_t> g_seenLeaveKeys[kTargetsSize][kFirstSeenKeys] = {};
std::atomic<unsigned> g_seenLeaveCount[kTargetsSize] = {};

/**
 * Buckets a return value into a small class so a MEANINGFUL CHANGE (bail 5's table-base
 * ret vs bail 3's index-or-minus-one vs a pass) is a new key, while repetitions of the
 * same verdict are not. Verified against the p2-161/162b/163/164 forensics: bail 5 reads
 * base & ~0xFF (class 2), bail 3 with idx < 0 reads all-ones (class 1), bail 3 with
 * idx >= 0 reads a small index (class 3), a pass reads 0 (class 0).
 */
[[nodiscard]] unsigned classify_ret(std::uint64_t ret) noexcept {
    if (ret == 0ULL) {
        return 0U;
    }
    if (ret == 0xFFFFFFFFFFFFFFFFULL) {
        return 1U;
    }
    if ((ret & 0xFFULL) == 0ULL && ret >= 0x10000ULL) {
        return 2U;
    }
    if (ret < 0x100ULL) {
        return 3U;
    }
    return 4U;
}

/** True the first time `key` is seen for this target (lock-free, racy, monotonic). */
[[nodiscard]] bool leave_key_first_seen(std::size_t index, std::uint64_t key) noexcept {
    const unsigned count = g_seenLeaveCount[index].load(std::memory_order_relaxed);
    for (unsigned i = 0; i < count && i < kFirstSeenKeys; ++i) {
        if (g_seenLeaveKeys[index][i].load(std::memory_order_relaxed) == key) {
            return false;
        }
    }
    if (count < kFirstSeenKeys) {
        g_seenLeaveKeys[index][count].store(key, std::memory_order_relaxed);
        g_seenLeaveCount[index].store(count + 1U, std::memory_order_relaxed);
    }
    return true;
}

/**
 * The entity-index manager's ENTIRE decision surface in one line: both masks' popcounts,
 * both tokens, both water marks and the pool's sent flag. Every gate on the lifecycle
 * chain reads one of these fields, so one line per call site says which gate closed and
 * on what value - instead of inferring it from a downstream silence, which is how this
 * lane spent six boots. Emitted on ENTER and again on LEAVE so a fill or a drain shows
 * up as a delta rather than a snapshot.
 *
 * Safety: [mgr+8] is dereferenced unconditionally by init, fill and sync themselves at
 * exactly these call sites, and [sub+0x10] is null-checked here the same way they check
 * it. No read here is one the callee does not also perform.
 */
void emit_manager_probe(std::size_t index, const char* fn, const char* when,
                        std::uint64_t call, const void* mgr) noexcept {
    if (mgr == nullptr) {
        return;
    }
    const void* const sub = *static_cast<const void* const*>(at(mgr, kMgrSubObject));
    const void* const pool =
        (sub == nullptr) ? nullptr : *static_cast<const void* const*>(at(sub, kPoolFromSub));
    const unsigned mgrFree = mask_popcount(at(mgr, kMgrFreeMask));
    const std::uint32_t low = *static_cast<const std::uint32_t*>(at(mgr, kMgrWaterLow));
    const std::uint32_t high = *static_cast<const std::uint32_t*>(at(mgr, kMgrWaterHigh));
    unsigned poolFree = 0U;
    std::uint32_t fillToken = 0U;
    std::uint32_t syncToken = 0U;
    unsigned sent = 0U;
    if (pool != nullptr) {
        poolFree = mask_popcount(at(pool, kPoolFreeMask));
        fillToken = *static_cast<const std::uint32_t*>(at(pool, kPoolFillToken));
        syncToken = *static_cast<const std::uint32_t*>(at(pool, kPoolSyncToken));
        sent = *static_cast<const std::uint8_t*>(at(pool, kPoolSentFlag));
    }
    // Collapse the whole decision surface to one value; emit only when it moves.
    const std::uint64_t fingerprint =
        (static_cast<std::uint64_t>(mgrFree) << 40) ^ (static_cast<std::uint64_t>(poolFree) << 24)
        ^ (static_cast<std::uint64_t>(fillToken) << 8) ^ static_cast<std::uint64_t>(syncToken)
        ^ (reinterpret_cast<std::uintptr_t>(pool) << 3) ^ static_cast<std::uint64_t>(sent);
    if (!probe_changed(index, fingerprint)) {
        return;
    }
    std::array<char, 320> text{};
    const int written = std::snprintf(
        text.data(), text.size(),
        "ev=mtrace stage=probe fn=%s when=%s call=%llu mgr=0x%llX pool=0x%llX "
        "mgr_free=%u pool_free=%u low=%u high=%u fill_tok=0x%X sync_tok=0x%X sent=0x%02X",
        fn, when, static_cast<unsigned long long>(call),
        reinterpret_cast<unsigned long long>(mgr), reinterpret_cast<unsigned long long>(pool),
        mgrFree, poolFree, low, high, fillToken, syncToken, sent);
    if (written > 0) {
        emit(text.data(), static_cast<std::size_t>(written));
    }
}

/**
 * The allocator's own view: how many slots were actually free when it scanned. This is
 * the measurement that separates "the mask is empty" (a conclusion the lane has only ever
 * INFERRED from a -1 return) from "the allocator reads something else" - pre-named
 * outcome (e) of the p2-144 brief, the one that abandons the mask theory outright.
 * Uncapped by the detail budget: idx_alloc is a cold path (26-31 calls per boot) and a
 * budget-gated probe is exactly how three previous boots lost their answer.
 */
void emit_alloc_probe(const char* fn, const char* when, std::uint64_t call,
                      const void* mgr) noexcept {
    if (mgr == nullptr) {
        return;
    }
    std::array<char, 192> text{};
    const int written = std::snprintf(
        text.data(), text.size(),
        "ev=mtrace stage=probe fn=%s when=%s call=%llu mgr=0x%llX mgr_free=%u",
        fn, when, static_cast<unsigned long long>(call),
        reinterpret_cast<unsigned long long>(mgr), mask_popcount(at(mgr, kMgrFreeMask)));
    if (written > 0) {
        emit(text.data(), static_cast<std::size_t>(written));
    }
}

/**
 * A predicate's return value, emitted only when it CHANGES. For a gate called tens of
 * thousands of times this yields a handful of lines that are exactly the transitions -
 * and, compared across the two machines, names which side is which.
 */
void emit_retwatch(std::size_t index, const char* fn, std::uint64_t call,
                   std::uint64_t result) noexcept {
    // The callees here return a BOOL IN AL; the upper RAX bits are undefined. Reading the
    // full register as the value is the 0x80000001 misread that cost this session a
    // retraction - mask to the declared width and print both.
    const std::uint64_t declared = result & 0xFFU;
    if (!probe_changed(index, declared)) {
        return;
    }
    std::array<char, 192> text{};
    const int written = std::snprintf(
        text.data(), text.size(),
        "ev=mtrace stage=retwatch fn=%s call=%llu al=%llu raw=0x%llX",
        fn, static_cast<unsigned long long>(call),
        static_cast<unsigned long long>(declared),
        static_cast<unsigned long long>(result));
    if (written > 0) {
        emit(text.data(), static_cast<std::size_t>(written));
    }
}

/**
 * The pool dispatcher's TYPE argument, one line per DISTINCT type ever seen.
 *
 * 0x1404F7DF0 receives the pool in rcx and the activity-message type in r8d, then walks
 * the 21-entry table at 0x141F92360 (`cmp dword [rdx], r15d`, stride 0x10) to find a
 * handler. p2-154's whole ambiguity is whether a type-45 body ever arrives here.
 *
 * A per-type bitmap rather than a call budget, deliberately: the early pool traffic is
 * hot and the body under test arrives ~250 s into the dwell, so a budget would be spent
 * before the interesting call - which is exactly how three earlier boots lost their
 * answer ("BUDGET OBSERVERS PER EVENT CLASS"). One line per distinct type is both
 * flood-proof and complete: the set of types this client dispatches IS the measurement.
 */
void emit_pooldisp(const char* fn, std::uint64_t call, std::uint64_t callerRva,
                   std::uint64_t type, const void* pool) noexcept {
    static std::atomic<std::uint64_t> seenLow{0};   // types 0..63
    static std::atomic<std::uint32_t> highCount{0}; // anything above, capped
    if (type < 64) {
        const std::uint64_t bit = 1ULL << type;
        const std::uint64_t prev = seenLow.fetch_or(bit, std::memory_order_relaxed);
        if ((prev & bit) != 0) {
            return;
        }
    } else if (highCount.fetch_add(1, std::memory_order_relaxed) >= 8) {
        return;
    }
    std::array<char, 192> text{};
    const int written = std::snprintf(
        text.data(), text.size(),
        "ev=mtrace stage=pooldisp fn=%s call=%llu caller_rva=0x%llX type=%llu "
        "type_hex=0x%llX pool=0x%llX first_seen=1",
        fn, static_cast<unsigned long long>(call),
        static_cast<unsigned long long>(callerRva),
        static_cast<unsigned long long>(type),
        static_cast<unsigned long long>(type),
        reinterpret_cast<unsigned long long>(pool));
    if (written > 0) {
        emit(text.data(), static_cast<std::size_t>(written));
    }
}

/**
 * The whole machine-id tracking array, at a pool handler's enter and leave.
 *
 * Layout (20.244 R1, femu-validated): count at pool+0x602B8, then rows of TEN bytes -
 * machine id at +0x602BC, the "contactable" byte at +0x602C4, the release latch at
 * +0x602C5. Logging the array on BOTH sides of the call is what separates the three
 * readings p2-154 could not: handler never ran / ran and wrote nothing / ran and wrote a
 * row we were not watching.
 *
 * GUARDED, because a bad dereference inside a detour hangs the client at Tower entry -
 * that cost a boot on 2026-08-31 (the memidx_alloc rdx read). The pointer must be
 * non-tiny and aligned, and the count must be plausible before any row is touched; an
 * implausible count means rcx is not the pool and the probe says so instead of reading.
 */
void emit_poolc4(const char* fn, const char* phase, std::uint64_t call,
                 const void* rcx) noexcept {
    const auto pool = reinterpret_cast<std::uintptr_t>(rcx);
    if (pool < 0x10000U || (pool & 7U) != 0U) {
        std::array<char, 160> bad{};
        const int w = std::snprintf(bad.data(), bad.size(),
            "ev=mtrace stage=poolc4 fn=%s when=%s call=%llu result=refused "
            "why=not-a-pointer rcx=0x%llX",
            fn, phase, static_cast<unsigned long long>(call),
            static_cast<unsigned long long>(pool));
        if (w > 0) { emit(bad.data(), static_cast<std::size_t>(w)); }
        return;
    }
    const auto* base = reinterpret_cast<const std::uint8_t*>(pool);
    std::uint32_t count = 0;
    std::memcpy(&count, base + 0x602B8, sizeof count);
    if (count > 64U) {
        std::array<char, 160> bad{};
        const int w = std::snprintf(bad.data(), bad.size(),
            "ev=mtrace stage=poolc4 fn=%s when=%s call=%llu result=refused "
            "why=count-implausible pool=0x%llX count=%lu",
            fn, phase, static_cast<unsigned long long>(call),
            static_cast<unsigned long long>(pool),
            static_cast<unsigned long>(count));
        if (w > 0) { emit(bad.data(), static_cast<std::size_t>(w)); }
        return;
    }
    std::array<char, 448> text{};
    int written = std::snprintf(
        text.data(), text.size(),
        "ev=mtrace stage=poolc4 fn=%s when=%s call=%llu pool=0x%llX rows=%lu",
        fn, phase, static_cast<unsigned long long>(call),
        static_cast<unsigned long long>(pool), static_cast<unsigned long>(count));
    const std::uint32_t shown = count < 6U ? count : 6U;
    for (std::uint32_t i = 0; i < shown && written > 0; ++i) {
        const std::size_t row = 0x602BCU + static_cast<std::size_t>(i) * 10U;
        std::uint64_t mid = 0;
        std::memcpy(&mid, base + row, sizeof mid);
        const unsigned c4 = base[row + 8];
        const unsigned latch = base[row + 9];
        written += std::snprintf(text.data() + written,
                                 text.size() - static_cast<std::size_t>(written),
                                 " | r%lu mid=0x%llX c4=0x%02X latch=0x%02X",
                                 static_cast<unsigned long>(i),
                                 static_cast<unsigned long long>(mid), c4, latch);
    }
    if (written > 0) {
        emit(text.data(), static_cast<std::size_t>(written));
    }
}

/**
 * The +0x602C4 reader's QUESTION: which pool, and which machine id.
 *
 * p2-155 established the answer is always zero while the row we marked reads one
 * (20.248 R3). Either the evaluator asks about a different machine id - each client's OWN
 * row stayed clear - or it holds a different pool object, and p2-155 proved a client can
 * have more than one. Logging the pair, once per distinct pair, separates those without
 * another boot.
 *
 * Guarded like every other pointer read in this file: rdx is a POINTER TO the id, and
 * dereferencing a bad one inside a detour hangs the client (the 2026-08-31 freeze).
 */
void emit_c4query(const char* fn, std::uint64_t call, const void* rcx,
                  const void* rdx) noexcept {
    const auto pool = reinterpret_cast<std::uintptr_t>(rcx);
    const auto midPtr = reinterpret_cast<std::uintptr_t>(rdx);
    if (pool < 0x10000U || (pool & 7U) != 0U || midPtr < 0x10000U || (midPtr & 7U) != 0U) {
        return;
    }
    std::uint64_t mid = 0;
    std::memcpy(&mid, reinterpret_cast<const void*>(midPtr), sizeof mid);
    // One line per distinct (pool, id) pair. A tiny fixed table, not a hash set: the
    // evaluator's query set is a handful of entries, and a full table simply stops
    // emitting rather than growing or flooding.
    struct Pair { std::uintptr_t pool; std::uint64_t mid; };
    static std::array<Pair, 16> seen{};
    static std::atomic<std::size_t> seenCount{0};
    const std::size_t have = seenCount.load(std::memory_order_relaxed);
    for (std::size_t i = 0; i < have && i < seen.size(); ++i) {
        if (seen[i].pool == pool && seen[i].mid == mid) {
            return;
        }
    }
    if (have >= seen.size()) {
        return;
    }
    seen[have] = Pair{pool, mid};
    seenCount.store(have + 1, std::memory_order_relaxed);
    std::array<char, 192> text{};
    const int written = std::snprintf(
        text.data(), text.size(),
        "ev=mtrace stage=c4query fn=%s call=%llu pool=0x%llX asks_mid=0x%llX first_seen=1",
        fn, static_cast<unsigned long long>(call),
        static_cast<unsigned long long>(pool),
        static_cast<unsigned long long>(mid));
    if (written > 0) {
        emit(text.data(), static_cast<std::size_t>(written));
    }
}

/**
 * Operand A of gate 2. The callee returned the member record; [ret+0x818] is the field the
 * loop compares against gate1's out-slot, and a mismatch is what skips a member. Logged as
 * a QWORD because the comparison is `mov rax,[rdi+0x818]; cmp rax,[rsp+0x68]` - 64-bit.
 * Guarded the same way the out-param read is: a record pointer that is null, in the first
 * page, or misaligned is a wrong-register bug, not a record.
 */
void emit_member_probe(const char* fn, std::uint64_t call, std::uint64_t record) noexcept {
    const auto ptr = static_cast<std::uintptr_t>(record);
    if (ptr < 0x10000U || (ptr & 7U) != 0U) {
        std::array<char, 160> text{};
        const int w = std::snprintf(text.data(), text.size(),
            "ev=mtrace stage=member fn=%s call=%llu result=refused why=not-a-record rec=0x%llX",
            fn, static_cast<unsigned long long>(call), static_cast<unsigned long long>(record));
        if (w > 0) { emit(text.data(), static_cast<std::size_t>(w)); }
        return;
    }
    const auto owner = *reinterpret_cast<const std::uint64_t*>(ptr + kMemberOwnerField);
    std::array<char, 176> text{};
    const int written = std::snprintf(
        text.data(), text.size(),
        "ev=mtrace stage=member fn=%s call=%llu rec=0x%llX owner=0x%llX",
        fn, static_cast<unsigned long long>(call),
        static_cast<unsigned long long>(record), static_cast<unsigned long long>(owner));
    if (written > 0) {
        emit(text.data(), static_cast<std::size_t>(written));
    }
}

/**
 * The 5th-8th stack arguments. 0x141703910 receives the two predicate results here
 * (r8d = 0x1404DF620's, arg6 = 0x1404DF650's), and both predicates are gap leaves too
 * small to hook directly - so this is the only way to see what they decided.
 */
void emit_stackargs(const char* fn, std::uint64_t call, const void* a5, const void* a6,
                    const void* a7, const void* a8) noexcept {
    std::array<char, 208> text{};
    const int w = std::snprintf(text.data(), text.size(),
        "ev=mtrace stage=stackargs fn=%s call=%llu a5=0x%llX a6=0x%llX a7=0x%llX a8=0x%llX",
        fn, static_cast<unsigned long long>(call),
        reinterpret_cast<unsigned long long>(a5), reinterpret_cast<unsigned long long>(a6),
        reinterpret_cast<unsigned long long>(a7), reinterpret_cast<unsigned long long>(a8));
    if (w > 0) { emit(text.data(), static_cast<std::size_t>(w)); }
}

/**
 * The 31-slot registry the construction chain writes into, read off 0x1416FF3C0's own rcx.
 * 20.224 R6 could not identify this object from the dump (it is NOT the entity manager -
 * mgr+0x170 holds the 6-byte per-slot record pattern instead); here it names itself.
 */
void emit_registry(const char* fn, const char* when, std::uint64_t call,
                   const void* owner) noexcept {
    const auto p = reinterpret_cast<std::uintptr_t>(owner);
    if (p < 0x10000U || (p & 7U) != 0U) {
        return;
    }
    const auto count = *reinterpret_cast<const std::uint32_t*>(p + kRegistryCount);
    const auto slot0 = *reinterpret_cast<const std::uint64_t*>(p + kRegistrySlots);
    const auto slot1 = *reinterpret_cast<const std::uint64_t*>(p + kRegistrySlots + 8);
    std::array<char, 208> text{};
    const int w = std::snprintf(text.data(), text.size(),
        "ev=mtrace stage=registry fn=%s when=%s call=%llu owner=0x%llX count=%u "
        "slot0=0x%llX slot1=0x%llX",
        fn, when, static_cast<unsigned long long>(call),
        static_cast<unsigned long long>(p), count,
        static_cast<unsigned long long>(slot0), static_cast<unsigned long long>(slot1));
    if (w > 0) { emit(text.data(), static_cast<std::size_t>(w)); }
}

/**
 * THE ANSWER LINE. get-or-create returns an INDEX in eax or -1 for refused. Only the low
 * 32 bits are the value; printing the full register beside it and stating the verdict in
 * words is the 0x80000001 retraction turned into a habit.
 */
void emit_retidx(const char* fn, std::uint64_t call, std::uint64_t result) noexcept {
    const auto eax = static_cast<std::uint32_t>(result & 0xFFFFFFFFU);
    std::array<char, 192> text{};
    const int w = std::snprintf(text.data(), text.size(),
        "ev=mtrace stage=retidx fn=%s call=%llu eax=0x%08X raw=0x%llX verdict=%s",
        fn, static_cast<unsigned long long>(call), eax,
        static_cast<unsigned long long>(result),
        (eax == 0xFFFFFFFFU) ? "REFUSED" : "index-granted");
    if (w > 0) { emit(text.data(), static_cast<std::size_t>(w)); }
}

/**
 * THE WHOLE CONSTRUCTION GATE (20.229), in one place. rcx is the object; [rcx]+0x6C38 is
 * the participant table; the five conditions live in three bitmasks and two per-record
 * bytes. Emitted only when the picture CHANGES, so a per-frame caller costs a few lines.
 *
 * Safety: the [rcx] deref mirrors 0x141702589 exactly, and the +0x6C38 step mirrors
 * 0x1404F5800 - every read here is one the callee itself performs on this same argument.
 * Both pointers are still guarded, and a bad one logs a refusal rather than faulting.
 */
void emit_ptable(std::size_t index, const char* fn, std::uint64_t call,
                 const void* arg) noexcept {
    const auto a = reinterpret_cast<std::uintptr_t>(arg);
    if (a < 0x10000U || (a & 7U) != 0U) {
        return;
    }
    const auto obj = *reinterpret_cast<const std::uintptr_t*>(a);
    if (obj < 0x10000U || (obj & 7U) != 0U) {
        std::array<char, 160> t{};
        const int w = std::snprintf(t.data(), t.size(),
            "ev=mtrace stage=ptable fn=%s call=%llu result=refused why=bad-obj obj=0x%llX",
            fn, static_cast<unsigned long long>(call),
            static_cast<unsigned long long>(obj));
        if (w > 0) { emit(t.data(), static_cast<std::size_t>(w)); }
        return;
    }
    const std::uintptr_t table = obj + kTableFromObj;
    const auto maskA = *reinterpret_cast<const std::uint32_t*>(table + kMaskA);
    const auto maskB = *reinterpret_cast<const std::uint32_t*>(table + kMaskB);
    const auto maskC = *reinterpret_cast<const std::uint32_t*>(table + kMaskC);
    // SELF INDEX (20.232 R1): 0x1404DD640 walks maskB comparing [table + i*stride + 8]
    // against the reference qword at [obj + 0x6C30]. Without this, "FAIL-cond3 on i=0"
    // cannot be told apart from "self, correctly excluded" - the wild-goose-chase guard.
    // The same walk names the PEER index (any other populated slot) for gate_wwatch.
    const auto selfRef =
        *reinterpret_cast<const std::uint64_t*>(obj + kTableFromObj - 8);  // obj+0x6C30
    int selfIdx = -1;
    int peerIdx = -1;
    std::uint64_t selfRec8 = 0;
    for (unsigned si = 0; si < kMaxParticipants; ++si) {
        if (((maskB >> si) & 1U) == 0U) {
            continue;
        }
        const auto rec8 =
            *reinterpret_cast<const std::uint64_t*>(table + si * kRecStride + 8U);
        if (rec8 == selfRef) {
            selfIdx = static_cast<int>(si);
            selfRec8 = rec8;
        } else if (peerIdx < 0 && rec8 != 0) {
            // A populated non-self record: the PEER. Zero identities are heap residue
            // (the p2-150 T4 lesson) and are never armed on.
            peerIdx = static_cast<int>(si);
        }
        if (selfIdx >= 0 && peerIdx >= 0) {
            break;
        }
    }
    // THE cond5 WIRE-WATCH (20.251): arm the hardware write-watches on this table's peer
    // and self gate bytes. Address arithmetic only here - no dereference the ptable read
    // above did not already perform - and the callee's arm_table is a two-atomic fast
    // path once armed, so the per-tick cost of 35k lifecycle calls is negligible.
    gate_wwatch::arm_table(table, selfIdx, peerIdx);
    // THE SLOT DUMP (20.282 follow-up): the card at +0x142 stayed zero while the field
    // decoded client-side, so the identity may land at a DIFFERENT slot offset (or at the
    // alternate claim source +0xEC). Dump each populated slot's first 0x300 bytes in three
    // 256-byte chunks whenever any card changed, so the next boot shows where the fork's
    // 86 bytes go - or that they never reach the slot.
    {
        std::uint64_t cardFp = 14695981039346656037ULL;
        std::uint8_t slotBuf[0x300] = {};
        for (unsigned i = 0; i < kMaxParticipants; ++i) {
            if (((maskB >> i) & 1U) == 0U) {
                continue;
            }
            if (gate_wwatch::safe_read(
                    reinterpret_cast<const void*>(table
                                                  + static_cast<std::uintptr_t>(i) * kRecStride),
                    slotBuf, sizeof(slotBuf))) {
                for (std::size_t b = 0; b < sizeof(slotBuf); ++b) {
                    cardFp = (cardFp ^ slotBuf[b]) * 16777619ULL;
                }
            } else {
                cardFp = (cardFp ^ (0x9E3779B9ULL + i)) * 16777619ULL;
            }
        }
        if (probe_changed(kCardGateSlot, cardFp)) {
            for (unsigned i = 0; i < kMaxParticipants; ++i) {
                if (((maskB >> i) & 1U) == 0U) {
                    continue;
                }
                if (!gate_wwatch::safe_read(
                        reinterpret_cast<const void*>(table
                                                      + static_cast<std::uintptr_t>(i)
                                                      * kRecStride),
                        slotBuf, sizeof(slotBuf))) {
                    continue;
                }
                for (std::size_t chunk = 0; chunk < 0x300; chunk += 0x100) {
                    std::array<char, 640> ct{};
                    int cw = std::snprintf(ct.data(), ct.size(),
                        "ev=mtrace stage=slot_dump fn=%s call=%llu slot=%u off=0x%02zX hex=",
                        fn, static_cast<unsigned long long>(call), i, chunk);
                    for (std::size_t b = 0; cw > 0 && b < 0x100; ++b) {
                        cw += std::snprintf(ct.data() + cw, ct.size() - cw, "%02x",
                                            static_cast<unsigned>(slotBuf[chunk + b]));
                    }
                    if (cw > 0) { emit(ct.data(), static_cast<std::size_t>(cw)); }
                }
                // The card line stays for the quick diff against resv_ident.
                std::array<char, 320> ct2{};
                int cw2 = std::snprintf(ct2.data(), ct2.size(),
                    "ev=mtrace stage=slot_card fn=%s call=%llu slot=%u card86=",
                    fn, static_cast<unsigned long long>(call), i);
                for (std::size_t b = 0; cw2 > 0 && b < 86; ++b) {
                    cw2 += std::snprintf(ct2.data() + cw2, ct2.size() - cw2, "%02x",
                                         static_cast<unsigned>(slotBuf[0x142 + b]));
                }
                if (cw2 > 0) { emit(ct2.data(), static_cast<std::size_t>(cw2)); }
            }
        }
    }
    if (!probe_changed(index, (static_cast<std::uint64_t>(maskA) << 32) ^ maskB ^
                              (static_cast<std::uint64_t>(maskC) << 16))) {
        return;
    }
    {
        std::array<char, 256> t{};
        const int w = std::snprintf(t.data(), t.size(),
            "ev=mtrace stage=ptable fn=%s call=%llu table=0x%llX "
            "maskA=0x%08X maskB=0x%08X maskC=0x%08X self=%d selfRef=0x%llX",
            fn, static_cast<unsigned long long>(call),
            static_cast<unsigned long long>(table), maskA, maskB, maskC,
            selfIdx, static_cast<unsigned long long>(selfRef));
        if (w > 0) { emit(t.data(), static_cast<std::size_t>(w)); }
    }
    // Per PRESENT participant (a set bit in maskB, which is what cond 1 iterates), report
    // the two remaining per-record conditions and say in words which one fails.
    // THE GATE POKE (p2-161), settings-gated, default off. Self's +0x00 is read first so
    // bit 1 can give the peer the same value: 20.258 R6 found it is the ONLY byte set on a
    // rendering record and zero on a non-rendering one, in 10,944 bytes.
    const std::uint32_t poke = core::settings::get().client.gatePoke;
    std::uint8_t selfState = 0;
    if (poke != 0U && selfIdx >= 0) {
        (void)gate_wwatch::safe_byte(
            reinterpret_cast<const void*>(table + static_cast<std::uintptr_t>(selfIdx)
                                          * kRecStride),
            &selfState);
    }
    for (unsigned i = 0; i < kMaxParticipants; ++i) {
        if (((maskB >> i) & 1U) == 0U) {
            continue;
        }
        const auto gateByte =
            *reinterpret_cast<const std::uint8_t*>(table + i * kRecStride + kRecGateByte);
        const auto nextByte =
            *reinterpret_cast<const std::uint8_t*>(table + (i + 1) * kRecStride);
        const auto rec8 =
            *reinterpret_cast<const std::uint64_t*>(table + i * kRecStride + 8U);
        const bool isSelf = (selfIdx == static_cast<int>(i));
        // THE ANCHOR, published for pubrest (p2-160 attempt 3). Taking it from the solo
        // baseline instead deadlocks: if a peer is already present when this client joins,
        // no solo image ever appears, so no baseline fires, so no anchor exists, so the
        // peer shot can never fire either. pgate walks the LIVE table and knows which
        // record is self authoritatively, which is the right place to learn it.
        if (isSelf && rec8 != 0U) {
            g_pubrestLocalIdentity.store(rec8, std::memory_order_relaxed);
        }
        const bool condA = ((maskA >> i) & 1U) != 0U;   // cond 3
        const bool condN = nextByte == 0U;              // cond 4 (0x1404DF600 false)
        const bool condG = ((gateByte >> 4) & 1U) != 0U;// cond 5 (0x1404DD470 true)
        const char* verdict = !condA ? "FAIL-cond3-maskA-bit-clear"
                            : !condN ? "FAIL-cond4-next-record-byte-nonzero"
                            : !condG ? "FAIL-cond5-bit4-of-+0x38-clear"
                                     : "ALL-PASS-would-construct";
        std::array<char, 288> t{};
        const int w = std::snprintf(t.data(), t.size(),
            "ev=mtrace stage=pgate fn=%s call=%llu i=%u self=%d rec8=0x%llX maskA_bit=%u "
            "f38=0x%02X bit4=%u next0=0x%02X verdict=%s",
            fn, static_cast<unsigned long long>(call), i, selfIdx,
            static_cast<unsigned long long>(rec8), condA ? 1U : 0U,
            gateByte, condG ? 1U : 0U, nextByte, verdict);
        if (w > 0) { emit(t.data(), static_cast<std::size_t>(w)); }

        // --- THE POKE. Behaviour, and the only write this DLL makes into game memory. ---
        // Applied AFTER the verdict line so the log always records the state as FOUND, then
        // separately what was forced: a probe that overwrites the thing it reports would
        // make the boot unreadable.
        // Re-applied every walk on purpose - the table is bulk-restored from the staging
        // image (20.254), which would erase a one-shot poke within a tick or two.
        if (poke != 0U && !isSelf) {
            const auto recBase = table + i * kRecStride;
            bool didGate = false;
            bool didState = false;
            std::uint8_t newGate = gateByte;
            std::uint8_t newState = 0;
            if ((poke & 1U) != 0U && !condG) {
                newGate = static_cast<std::uint8_t>(gateByte | 0x10U);
                didGate = gate_wwatch::safe_store(
                    reinterpret_cast<void*>(recBase + kRecGateByte), newGate);
            }
            if ((poke & 2U) != 0U && selfState != 0U) {
                std::uint8_t cur = 0;
                if (gate_wwatch::safe_byte(reinterpret_cast<const void*>(recBase), &cur)
                    && cur != selfState) {
                    newState = selfState;
                    didState = gate_wwatch::safe_store(
                        reinterpret_cast<void*>(recBase), selfState);
                }
            }
            if (didGate || didState) {
                // Novelty-gated on (record, what was written) so a per-tick re-poke costs
                // one line, while any CHANGE in what we are forcing is visible.
                const std::uint64_t sig = (static_cast<std::uint64_t>(i) << 32)
                                          ^ (static_cast<std::uint64_t>(newGate) << 8)
                                          ^ newState ^ (didGate ? 0x100ULL : 0ULL)
                                          ^ (didState ? 0x200ULL : 0ULL);
                if (probe_changed(index, sig)) {
                    std::array<char, 256> pt{};
                    const int pw = std::snprintf(pt.data(), pt.size(),
                        "ev=mtrace stage=gatepoke fn=%s call=%llu i=%u rec8=0x%llX "
                        "mask=0x%X f38_was=0x%02X f38_now=0x%02X gate_ok=%u "
                        "state_self=0x%02X state_ok=%u",
                        fn, static_cast<unsigned long long>(call), i,
                        static_cast<unsigned long long>(rec8), poke,
                        gateByte, newGate, didGate ? 1U : 0U,
                        selfState, didState ? 1U : 0U);
                    if (pw > 0) { emit(pt.data(), static_cast<std::size_t>(pw)); }
                }
            }
        }
    }
}

/**
 * THE PUBLISH/RESTORE OBSERVER (20.254). rcx = the copy-side object (its +0x80 is one
 * side of the bulk copy), rdx = the image id, r8 = the other side. When arg1+0x80 is a
 * known participant table this is a RESTORE (an image is being copied INTO the live
 * table - the write-back that reaches the gate bytes); when arg3 is a known table it is
 * a PUBLISH (table -> snapshot). The copy is offset-1:1 over [dest, dest+0x59260), so
 * the source's per-record gate bytes sit at src+0x38+i*0x2AC0 - logged for records 0..3
 * with their identities. On the first restore, the WHOLE source image is hexdumped once
 * (state_diff's dump pattern): the structure of the thing that would carry bit4 in
 * retail. Safety: every game-memory read is SEH-guarded via gate_wwatch::safe_byte /
 * safe_copy; emission is novelty-gated on (caller, args, gate-byte tuple) - no budget.
 */
void emit_pubrest(std::size_t index, const char* fn, const char* when, std::uint64_t call,
                  std::uintptr_t callerRva, const void* rcx, const void* rdx,
                  const void* r8) noexcept {
    const auto arg1 = reinterpret_cast<std::uintptr_t>(rcx);
    const auto arg3 = reinterpret_cast<std::uintptr_t>(r8);
    if (arg1 < 0x1000U || (arg1 & 7U) != 0U) {
        return;
    }
    const auto staging = arg1 + 0x80U;
    const bool restore = gate_wwatch::is_armed_table(staging);
    const bool publish = !restore && gate_wwatch::is_armed_table(arg3);
    const char* role = restore ? "restore" : (publish ? "publish" : "unknown");
    const bool isEnter = (when[0] == 'e');

    // Source-side gate bytes (arg3 is the source in both directions) and DEST-side gate
    // bytes (arg1+0x80) - the enter/leave delta of the dest tuple is the "did this call
    // change the dest" measurement. 0xFF = read failed (never a real gate value).
    // EIGHT records, not two (p2-160 attempt 3). Reading only records 0 and 1 assumes the
    // peer lands in slot 1. Nothing guarantees that - the live table has put the LOCAL
    // player in slot 1 (pgate: `i=1 self=1`), so a peer can equally sit at 2 or beyond, and
    // with a 2-record window it would have been invisible and the peer shot would never
    // have fired. Records past the image are best-effort: their failure must not clear
    // srcOk, which is a statement about record 0 only.
    constexpr unsigned kImgRecords = 8;
    std::uint8_t f38[kImgRecords];
    std::uint8_t f38d[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    std::uint64_t rec8[kImgRecords];
    for (unsigned i = 0; i < kImgRecords; ++i) {
        f38[i] = 0xFFU;
        rec8[i] = 0U;
    }
    bool srcOk = false;
    if (arg3 >= 0x1000U) {
        // srcOk == record 0 is readable. That is the minimum for the image to mean anything.
        std::uint8_t gate0 = 0xFFU;
        const bool gate0Ok = gate_wwatch::safe_byte(
            reinterpret_cast<const void*>(arg3 + 0x38U), &gate0);
        f38[0] = gate0Ok ? gate0 : 0xFFU;
        srcOk = gate0Ok
                && gate_wwatch::safe_read(reinterpret_cast<const void*>(arg3 + 8U),
                                          &rec8[0], sizeof(rec8[0]));
        for (unsigned i = 1; i < kImgRecords; ++i) {
            const auto base = arg3 + i * 0x2AC0U;
            if (!gate_wwatch::safe_byte(reinterpret_cast<const void*>(base + 0x38U),
                                        &f38[i])) {
                f38[i] = 0xFFU;
            }
            if (!gate_wwatch::safe_read(reinterpret_cast<const void*>(base + 8U),
                                        &rec8[i], sizeof(rec8[i]))) {
                rec8[i] = 0U;
            }
        }
    }
    for (unsigned i = 0; i < 4; ++i) {
        if (!gate_wwatch::safe_byte(
                reinterpret_cast<const void*>(staging + 0x38U + i * 0x2AC0U), &f38d[i])) {
            f38d[i] = 0xFFU;
        }
    }
    // The anchor, and the peer search over every scanned record.
    const std::uint64_t anchorId = g_pubrestLocalIdentity.load(std::memory_order_relaxed);
    const bool anchored = anchorId != 0U && rec8[0] == anchorId;
    int peerIdx = -1;
    if (anchored) {
        for (unsigned i = 1; i < kImgRecords; ++i) {
            if (rec8[i] != 0U && rec8[i] != anchorId) {
                peerIdx = static_cast<int>(i);
                break;
            }
        }
    }

    // A genuine peer image is ANCHORED - record 0 is this machine's own identity, as pgate
    // reports it from the live table - and some later record holds a different populated
    // identity. `rec8_1 != rec8_0` is NOT a peer test and cost a boot: attempt 2 saw
    // rec8_0 = 0x1A82CB013E294F94 (a byte-shifted view of the local key) with the LOCAL
    // identity in rec8_1, which satisfies !=, is stable and repeatable rather than a
    // one-off tear, and consumed the peer shot before the second machine had joined.
    const bool peerInImage = srcOk && anchored && peerIdx > 0;

    // Per-phase novelty (adversarial review #2): enter and leave each collapse repeats
    // of an identical call independently, so a hot stable path costs two lines total
    // while any arg/gate-byte change emits.
    //
    // peerInImage is IN the fingerprint. Without it the solo->peer transition is invisible
    // here: the restore's caller, args and gate bytes are all unchanged when a peer joins
    // (every f38 stays 0x00 - 907/907 samples in p2-150), so the one call this boot exists
    // to see would have collapsed into the solo path's already-emitted line.
    const std::uint64_t fingerprint =
        callerRva ^ arg1 ^ arg3 ^ (restore ? 0x8000000000000000ULL : 0ULL)
        ^ (peerInImage ? 0x4000000000000000ULL : 0ULL)
        ^ static_cast<std::uint64_t>(f38[0]) ^ (static_cast<std::uint64_t>(f38[1]) << 8)
        ^ (static_cast<std::uint64_t>(f38[2]) << 16) ^ (static_cast<std::uint64_t>(f38[3]) << 24)
        ^ static_cast<std::uint64_t>(f38d[0]) ^ (static_cast<std::uint64_t>(f38d[1]) << 8)
        ^ (static_cast<std::uint64_t>(f38d[2]) << 16) ^ (static_cast<std::uint64_t>(f38d[3]) << 24);
    auto& lastSeen = isEnter ? g_pubrestLastEnter[index] : g_pubrestLastLeave[index];
    const std::uint64_t prev = lastSeen.load(std::memory_order_relaxed);
    const bool first = !g_pubrestSeen[index].load(std::memory_order_relaxed);
    // Suppression now skips the LINE ONLY - it must never skip the image dump below.
    // The old `return` here put the dump behind the novelty gate, so a peer-bearing
    // restore that repeated an already-seen fingerprint could be dropped before the
    // dump was ever considered. A budget that silences the summary must not also
    // silence the artifact the boot is for.
    const bool suppressed = !first && prev == fingerprint;
    lastSeen.store(fingerprint, std::memory_order_relaxed);
    g_pubrestSeen[index].store(true, std::memory_order_relaxed);

    if (!suppressed) {
        std::array<char, 640> t{};
        const int w = std::snprintf(t.data(), t.size(),
            "ev=mtrace stage=pubrest fn=%s when=%s call=%llu caller_rva=0x%llX role=%s "
            "arg1=0x%llX image_id=0x%llX src=0x%llX staging=0x%llX src_ok=%u "
            "f38src_0..7=%02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x "
            "f38dest_0..3=%02x,%02x,%02x,%02x anchored=%u peer_idx=%d "
            "rec8_0=0x%llX rec8_1=0x%llX rec8_2=0x%llX rec8_3=0x%llX",
            fn, when, static_cast<unsigned long long>(call),
            static_cast<unsigned long long>(callerRva), role,
            static_cast<unsigned long long>(arg1),
            reinterpret_cast<unsigned long long>(rdx),
            static_cast<unsigned long long>(arg3),
            static_cast<unsigned long long>(staging), srcOk ? 1U : 0U,
            f38[0], f38[1], f38[2], f38[3], f38[4], f38[5], f38[6], f38[7],
            f38d[0], f38d[1], f38d[2], f38d[3], anchored ? 1U : 0U, peerIdx,
            static_cast<unsigned long long>(rec8[0]),
            static_cast<unsigned long long>(rec8[1]),
            static_cast<unsigned long long>(rec8[2]),
            static_cast<unsigned long long>(rec8[3]));
        if (w > 0) {
            emit(t.data(), static_cast<std::size_t>(w));
        }
    }
    // TWO-SHOT full source-image hexdump, enter only (adversarial review #6: enter+leave
    // would double-burn the cap; ~1,427 lines of 0x100 each per shot, chunk reads are one
    // SEH-guarded 256-byte copy per line, not per byte).
    //
    // NOT gated on role (p2-160, measured): the gate used to require role==restore, and in
    // a full paired dwell NOTHING ever classified as one - 24 calls, 24 x role=unknown,
    // 0 dumps. It could not have been otherwise: the restore is obfuscated-direct and
    // BYPASSES 0x1403CB340, which is the function this hook detours, so a restore never
    // arrives here by construction. What DOES arrive is the publish side, and that is where
    // the wanted image lives - 8 of those 24 calls carried a genuine peer in their source
    // image (rec8_1 = the other machine's identity) at caller_rva 0x16E62AD, inside the
    // message-driven publish 0x1416E6250 of 20.255.
    //
    // The dump is therefore gated on what it actually needs - a READABLE SOURCE IMAGE of a
    // known shape - and not on a role classification that answers a different question.
    //
    // A GENUINE peer in the source image is `record 1 populated AND not the local
    // identity`. Record 1 holding rec8_0's value is NOT a peer: p2-150's pgate saw the
    // local identity sitting in slot 1 while the table was in its one-member state, so
    // `rec8_1 != 0` alone would fire shot 1 on a solo image and waste the boot.
    //
    // rec8_0 != 0 is required for BOTH shots: an image whose record 0 carries no identity
    // is not a membership image at all. p2-160's first pubrest call had rec8_0 = rec8_1 = 0
    // (src was the participant table before anything populated it), and taking THAT as the
    // solo baseline would diff two unrelated objects and read the difference as meaning.
    // The baseline must be the same KIND of thing as the peer image; the headers carry
    // src= and caller_rva= on both shots so the analysis can confirm it rather than assume.
    if (isEnter && srcOk && rec8[0] != 0U) {
        // THE STABILITY GATE IS GONE, and both shots are gated on the ANCHOR instead.
        // Replaying the shipped logic over attempts 1 and 2 killed it twice over:
        //   - a single shared slot let an interleaved peer image break the baseline's
        //     streak, so the BASELINE stopped firing on attempt 1's own recorded lines;
        //   - it spends margin where margin is scarcest - the peer window is ~6 bodies and
        //     attempt 1 saw the genuine tuple three times, so demanding a second sighting
        //     risks losing a short pairing outright.
        // The anchor is strictly stronger and needs only one sighting: it rejects BOTH bad
        // images seen so far - attempt 1's one-off tear and attempt 2's stable shifted view
        // - because neither carries this machine's identity in record 0.
        // The shot a call can satisfy is decided by the image's OWN shape, never by which
        // flag happens to be unclaimed: that keeps shot 0 a genuine solo image and shot 1
        // a genuine peer image, so their diff means what the contract says it means. If a
        // peer is present from the first restore onward, shot 0 simply never fires - an
        // honest gap, not a mislabelled dump.
        // ANCHOR: the peer shot fires only on an image whose record 0 IS the local identity
        // (learned from the solo baseline, below). Until the baseline has run there is no
        // anchor and no peer dump - which is also the natural order, the solo image being
        // the one that exists first.
        // BOTH shots require the anchor. Without it on the baseline, attempt 2's shifted
        // image (record 0 = 0x1A82CB013E294F94, not this machine) qualifies as "not a peer"
        // and becomes the baseline - and then the diff compares a garbage image against a
        // real one and every difference reads as meaning.
        const bool wantPeer =
            peerInImage && g_pubrestPeerDumped.load(std::memory_order_relaxed) == 0U;
        const bool wantBaseline = anchored && !peerInImage
                                  && g_pubrestDumped.load(std::memory_order_relaxed) == 0U;
        if (wantBaseline || wantPeer) {
            // Shot index names WHICH image a line belongs to, so the offline diff can
            // separate the two dumps; the old line hardcoded idx=0.
            const unsigned shot = wantPeer ? 1U : 0U;
            if (wantPeer) {
                g_pubrestPeerDumped.store(1U, std::memory_order_relaxed);
            } else {
                g_pubrestDumped.store(1U, std::memory_order_relaxed);
            }
            // Self-describing header (U14): a hexdump with no provenance cannot be
            // attributed to a shape after the fact.
            {
                std::array<char, 320> h{};
                const int hw = std::snprintf(h.data(), h.size(),
                    "ev=mtrace stage=pubrestimg result=begin idx=%u peer=%u role=%s "
                    "src=0x%llX call=%llu caller_rva=0x%llX rec8_0=0x%llX rec8_1=0x%llX "
                    "f38src_0..3=%02x,%02x,%02x,%02x",
                    shot, peerInImage ? 1U : 0U, role,
                    static_cast<unsigned long long>(arg3),
                    static_cast<unsigned long long>(call),
                    static_cast<unsigned long long>(callerRva),
                    static_cast<unsigned long long>(rec8[0]),
                    static_cast<unsigned long long>(rec8[1]),
                    f38[0], f38[1], f38[2], f38[3]);
                if (hw > 0) {
                    emit(h.data(), static_cast<std::size_t>(hw));
                }
            }
            constexpr std::uintptr_t kImageBytes = 0x59260U;
            constexpr std::uintptr_t kChunk = 0x100U;
            std::array<std::uint8_t, kChunk> chunk{};
            std::uintptr_t done = 0;
            for (std::uintptr_t off = 0; off < kImageBytes; off += kChunk) {
                if (!gate_wwatch::safe_read(reinterpret_cast<const void*>(arg3 + off),
                                            chunk.data(), chunk.size())) {
                    break;  // unreadable region: stop the dump here, honestly
                }
                std::array<char, 1024> t{};
                int w = std::snprintf(t.data(), t.size(),
                    "ev=mtrace stage=pubrestimg idx=%u src=0x%llX off=0x%llX hex=",
                    shot,
                    static_cast<unsigned long long>(arg3),
                    static_cast<unsigned long long>(off));
                for (std::size_t b = 0; w > 0 && b < chunk.size(); ++b) {
                    w += std::snprintf(t.data() + w, t.size() - static_cast<std::size_t>(w),
                                       "%02x", chunk[b]);
                }
                if (w > 0) {
                    emit(t.data(), static_cast<std::size_t>(w));
                }
                done = (off + kChunk > kImageBytes) ? kImageBytes : off + kChunk;
            }
            // `bytes=` is the honest coverage figure: a short dump must not be read as a
            // full image that happens to end early.
            std::array<char, 160> d{};
            const int dw = std::snprintf(d.data(), d.size(),
                "ev=mtrace stage=pubrestimg result=done idx=%u peer=%u bytes=0x%llX",
                shot, peerInImage ? 1U : 0U,
                static_cast<unsigned long long>(done));
            if (dw > 0) {
                emit(d.data(), static_cast<std::size_t>(dw));
            }
        }
    }
}

/**
 * The tracking-row adders' enter probe (p2-152). rcx is the pool, rdx points at the
 * machine-id qword the callee will append (verified off BOTH callees' own prologues:
 * the canonical adder does `mov rax,[rdx]`, the fixup does `mov rbx,rdx; cmp [..],rbx`).
 * The caller RVA at THIS entry is the call site (+5), which is exactly 20.241 R5's
 * discriminator: the genuine feed vs the self-heal, per machine-id.
 * The machine-id VALUE is logged, never just the pointer - the pointer says nothing
 * about identity, and the p2-145 out-param freeze is the standing warning against
 * dereferencing a mis-declared register. Guarded the same way the member probe guards
 * its record pointer; a refusal logs a line rather than faulting.
 */
void emit_trackadd(std::size_t index, const char* fn, std::uint64_t call,
                   std::uintptr_t callerRva, const void* midPtr, const void* pool) noexcept {
    if (g_trackEmits[index].fetch_add(1, std::memory_order_relaxed) >= kTrackProbeCap) {
        return;
    }
    if (midPtr == nullptr || reinterpret_cast<std::uintptr_t>(midPtr) < 0x10000U
        || (reinterpret_cast<std::uintptr_t>(midPtr) & 7U) != 0U) {
        std::array<char, 176> t{};
        const int w = std::snprintf(t.data(), t.size(),
            "ev=mtrace stage=trackadd fn=%s call=%llu caller_rva=0x%llX "
            "result=refused why=not-a-pointer rdx=0x%llX pool=0x%llX",
            fn, static_cast<unsigned long long>(call),
            static_cast<unsigned long long>(callerRva),
            reinterpret_cast<unsigned long long>(midPtr),
            reinterpret_cast<unsigned long long>(pool));
        if (w > 0) { emit(t.data(), static_cast<std::size_t>(w)); }
        return;
    }
    const auto mid = *reinterpret_cast<const std::uint64_t*>(midPtr);
    // Change-gate on the whole answer triple; a repeated (caller, mid, pool) pair is
    // the steady state and one line covers it.
    const std::uint64_t fingerprint =
        (static_cast<std::uint64_t>(callerRva) << 4) ^ mid
        ^ (reinterpret_cast<std::uintptr_t>(pool) << 1);
    if (!probe_changed(index, fingerprint)) {
        return;
    }
    std::array<char, 208> t{};
    const int w = std::snprintf(t.data(), t.size(),
        "ev=mtrace stage=trackadd fn=%s call=%llu caller_rva=0x%llX mid=0x%llX pool=0x%llX",
        fn, static_cast<unsigned long long>(call),
        static_cast<unsigned long long>(callerRva),
        static_cast<unsigned long long>(mid),
        reinterpret_cast<unsigned long long>(pool));
    if (w > 0) { emit(t.data(), static_cast<std::size_t>(w)); }
}

/** Dispatches whichever structured probe this target declared, on enter. */
/**
 * THE RESERVATION-TABLE CONNECTION-LADDER READER (W2, 20.271 R5). The lookup
 * 0x1417C40F0 runs on the reserve path (joins) and, with the poke armed, on every
 * guard pass - each leave is a sampling opportunity. The table base comes from the
 * obfuscated accessor 0x1417CF0E0, which is CALLED here (same thread, same keys the
 * game itself uses; never detoured - the p2-147a class). Walks all 62 x 0x41F0
 * records, reads the two lifecycle states (+0x30E8, +0x1DC0) SEH-guarded, folds a
 * fingerprint, and emits ONLY on a change: one summary line plus up to eight
 * per-record lines naming the states and the identity prefix. Read-only: no writes
 * into game memory anywhere in this probe.
 */
void emit_resvtable(std::size_t index, const char* fn, std::uint64_t call) noexcept {
    using ResvBaseFn = void* (*)() noexcept;
    const auto accessor = reinterpret_cast<ResvBaseFn>(g_base + 0x17CF0E0);
    if (accessor == nullptr) {
        return;
    }
    const auto base = reinterpret_cast<std::uintptr_t>(accessor());
    if (base < 0x10000U) {
        if (probe_changed(index, 0ULL)) {
            std::array<char, 160> t{};
            const int w = std::snprintf(t.data(), t.size(),
                "ev=mtrace stage=resv fn=%s call=%llu base=0 result=no-base",
                fn, static_cast<unsigned long long>(call));
            if (w > 0) { emit(t.data(), static_cast<std::size_t>(w)); }
        }
        return;
    }
    constexpr std::uintptr_t kRecStride = 0x41F0;
    constexpr std::size_t kRecordCount = 62;
    constexpr std::uintptr_t kOffState1 = 0x30E8;   // guard predicate 2: ==4 established
    constexpr std::uintptr_t kOffState2 = 0x1DC0;   // guard predicate 3: ==5 connected
    constexpr std::uintptr_t kOffIdentity = 0x3144; // the 86-byte identity blob
    constexpr std::uintptr_t kOffMask = 0x3112;     // predicate 1's u16 participant mask
    constexpr std::uintptr_t kOffTouch = 0x4270;    // the touch-clear target (20.273 R1)
    std::uint32_t states1[kRecordCount]{};
    std::uint32_t states2[kRecordCount]{};
    std::uint64_t idents[kRecordCount]{};
    std::uint16_t masks[kRecordCount]{};
    std::uint64_t touch[kRecordCount]{};
    std::uint32_t nonzero = 0;
    std::uint64_t fingerprint = 14695981039346656037ULL;
    for (std::size_t r = 0; r < kRecordCount; ++r) {
        const auto rec = base + r * kRecStride;
        std::uint32_t s1 = 0;
        std::uint32_t s2 = 0;
        std::uint64_t ident = 0;
        std::uint16_t mask = 0;
        std::uint64_t touched = 0;
        const bool ok1 = gate_wwatch::safe_read(reinterpret_cast<const void*>(rec + kOffState1),
                                                &s1, sizeof(s1));
        const bool ok2 = gate_wwatch::safe_read(reinterpret_cast<const void*>(rec + kOffState2),
                                                &s2, sizeof(s2));
        const bool ok3 = gate_wwatch::safe_read(reinterpret_cast<const void*>(rec + kOffIdentity),
                                                &ident, sizeof(ident));
        const bool ok4 = gate_wwatch::safe_read(reinterpret_cast<const void*>(rec + kOffMask),
                                                &mask, sizeof(mask));
        const bool ok5 = gate_wwatch::safe_read(reinterpret_cast<const void*>(rec + kOffTouch),
                                                &touched, sizeof(touched));
        if (!ok1 || !ok2 || !ok3 || !ok4 || !ok5) {
            fingerprint = (fingerprint ^ (0x9E3779B9ULL + r)) * 16777619ULL;
            continue;
        }
        states1[r] = s1;
        states2[r] = s2;
        idents[r] = ident;
        masks[r] = mask;
        touch[r] = touched;
        if (s1 != 0U || s2 != 0U || ident != 0U) {
            ++nonzero;
        }
        fingerprint = (fingerprint ^ s1) * 16777619ULL;
        fingerprint = (fingerprint ^ s2) * 16777619ULL;
        fingerprint = (fingerprint ^ (ident >> 32)) * 16777619ULL;
        fingerprint = (fingerprint ^ (ident & 0xFFFFFFFFULL)) * 16777619ULL;
        fingerprint = (fingerprint ^ mask) * 16777619ULL;
        fingerprint = (fingerprint ^ touched) * 16777619ULL;
    }
    if (!probe_changed(index, fingerprint)) {
        return;
    }
    std::array<char, 192> t{};
    int w = std::snprintf(t.data(), t.size(),
        "ev=mtrace stage=resv fn=%s call=%llu base=0x%llX nonzero=%u fp=0x%016llX",
        fn, static_cast<unsigned long long>(call),
        static_cast<unsigned long long>(base), nonzero,
        static_cast<unsigned long long>(fingerprint));
    if (w > 0) { emit(t.data(), static_cast<std::size_t>(w)); }
    for (std::size_t r = 0; r < kRecordCount && w > 0; ++r) {
        if (states1[r] == 0U && states2[r] == 0U && idents[r] == 0U) {
            continue;
        }
        std::array<char, 224> rt{};
        w = std::snprintf(rt.data(), rt.size(),
            "ev=mtrace stage=resv_rec fn=%s call=%llu rec=%zu s30e8=%u s1dc0=%u "
            "mask=0x%04X touch=%lld ident=0x%016llX",
            fn, static_cast<unsigned long long>(call), r,
            states1[r], states2[r], masks[r],
            static_cast<long long>(touch[r]),
            static_cast<unsigned long long>(idents[r]));
        if (w > 0) { emit(rt.data(), static_cast<std::size_t>(w)); }
        // THE FULL CARD (20.277 R3 prerequisite ii): the probe logged 8 of 86 identity
        // bytes; the implementation boot needs the WHOLE 86 to verify the fork's emitted
        // transport identity landed byte-exact (prerequisite ii) and to capture the
        // memcmp-path byte (+0x55 in the 0x1403EA820 type gate). Emitted for every record
        // the summary line names, SEH-guarded like every read above.
        {
            std::uint8_t card[86] = {};
            if (gate_wwatch::safe_read(
                    reinterpret_cast<const void*>(base
                                                  + static_cast<std::uintptr_t>(r)
                                                  * kRecStride + kOffIdentity),
                    card, sizeof(card))) {
                std::array<char, 320> ct{};
                int cw = std::snprintf(ct.data(), ct.size(),
                    "ev=mtrace stage=resv_ident fn=%s call=%llu rec=%zu ident86=",
                    fn, static_cast<unsigned long long>(call), r);
                for (std::size_t b = 0; cw > 0 && b < sizeof(card); ++b) {
                    cw += std::snprintf(ct.data() + cw, ct.size() - cw, "%02x",
                                        static_cast<unsigned>(card[b]));
                }
                if (cw > 0) { emit(ct.data(), static_cast<std::size_t>(cw)); }
            }
        }
    }
}

void run_probe(std::size_t index, Probe probe, const char* fn, const char* when,
               std::uint64_t call, const void* rcx) noexcept {
    switch (probe) {
        case Probe::manager:
            emit_manager_probe(index, fn, when, call, rcx);
            break;
        case Probe::gatebit:
            emit_gatebit(index, fn, call, rcx);
            break;
        case Probe::alloc:
            emit_alloc_probe(fn, when, call, rcx);
            break;
        case Probe::retwatch:
        case Probe::none:
        default:
            break;
    }
}

/** The generic observer. `Index` gives each target its own trampoline and counters. */
template <std::size_t Index>
std::uint64_t __fastcall observe(void* rcx, void* rdx, void* r8, void* r9,
                                 void* a5, void* a6, void* a7, void* a8,
                                 void* a9, void* a10, void* a11, void* a12,
                                 void* a13, void* a14, void* a15, void* a16,
                                 void* a17, void* a18, void* a19, void* a20) noexcept {
    const std::uint64_t call = g_calls[Index].fetch_add(1, std::memory_order_relaxed) + 1U;
    const std::uint64_t total = g_total.fetch_add(1, std::memory_order_relaxed) + 1U;
    // The CALLER is the point of this instrument: a runtime-dispatched function cannot be
    // traced back to its invoker any other way (20.209).
    const auto caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
    // A filtered target logs NOTHING for calls from other sites - it still counts them,
    // so the census remains a true total while the budget is spent only on the call we came for.
    const std::uintptr_t callerRva = caller >= g_base ? caller - g_base : caller;
    const bool siteMatch =
        kTargets[Index].caller_filter == 0U || callerRva == kTargets[Index].caller_filter;
    const bool detail = siteMatch
                        && g_logged[Index].load(std::memory_order_relaxed) < kTargets[Index].budget;
    if (detail) {
        g_logged[Index].fetch_add(1, std::memory_order_relaxed);
        std::array<char, 224> text{};
        const int written = std::snprintf(
            text.data(), text.size(),
            "ev=mtrace stage=enter fn=%s call=%llu caller_rva=0x%llX "
            "rcx=0x%llX rdx=0x%llX r8=0x%llX r9=0x%llX",
            kTargets[Index].name, static_cast<unsigned long long>(call),
            static_cast<unsigned long long>(caller >= g_base ? caller - g_base : caller),
            reinterpret_cast<unsigned long long>(rcx), reinterpret_cast<unsigned long long>(rdx),
            reinterpret_cast<unsigned long long>(r8), reinterpret_cast<unsigned long long>(r9));
        if (written > 0) {
            emit(text.data(), static_cast<std::size_t>(written));
        }
    }
    // The argv dump is deliberately OUTSIDE the detail budget: the budget is consumed by
    // the noisiest early traffic (internal types 92/93) long before our join burst arrives,
    // and a dump gated on it never sees our types (20.217 amendment 3, observed twice).
    if (kTargets[Index].dump_rcx && rcx != nullptr) {
        const auto* obj = static_cast<const std::uint8_t*>(rcx);
        if (obj[0] == 20 || obj[0] == 21 || obj[0] == 30) {
            std::array<char, 96> hex{};
            int hw = std::snprintf(hex.data(), hex.size(),
                                   "ev=mtrace stage=argv fn=%s call=%llu obj0=",
                                   kTargets[Index].name,
                                   static_cast<unsigned long long>(call));
            for (std::size_t b = 0; b < 8 && hw > 0; ++b) {
                hw += std::snprintf(hex.data() + hw, hex.size() - hw, "%02x",
                                    static_cast<unsigned>(obj[b]));
            }
            if (hw > 0) {
                emit(hex.data(), static_cast<std::size_t>(hw));
            }
        }
    }
    // Structured probes run OUTSIDE the detail budget: every target carrying one is a
    // cold path (single-digit to low-tens of calls per boot), and a budget-gated probe is
    // precisely how three earlier boots lost their answer to a cap spent by noise.
    if (siteMatch) {
        run_probe(Index, kTargets[Index].probe, kTargets[Index].name, "enter", call, rcx);
        if (kTargets[Index].probe == Probe::stackargs
            || kTargets[Index].probe == Probe::gatebit) {
            emit_stackargs(kTargets[Index].name, call, a5, a6, a7, a8);
        }
        if (kTargets[Index].probe == Probe::registry) {
            emit_registry(kTargets[Index].name, "enter", call, rcx);
        }
        if (kTargets[Index].probe == Probe::ptable) {
            emit_ptable(Index, kTargets[Index].name, call, rcx);
        }
        if (kTargets[Index].probe == Probe::pubrest) {
            emit_pubrest(Index, kTargets[Index].name, "enter", call, callerRva,
                         rcx, rdx, r8);
        }
        if (kTargets[Index].probe == Probe::trackadd) {
            emit_trackadd(Index, kTargets[Index].name, call, callerRva, rdx, rcx);
        }
        if (kTargets[Index].probe == Probe::pooldisp) {
            // r8 is the activity-message TYPE (0x1404F7E26 `mov r15d, r8d`, then the
            // table walk compares it against each row's dword). Masked to 32 bits: the
            // callee reads r8d, and the upper half is not the caller's to promise -
            // the 0x80000001 retraction was exactly this class of misread.
            emit_pooldisp(kTargets[Index].name, call, callerRva,
                          reinterpret_cast<std::uint64_t>(r8) & 0xFFFFFFFFULL, rcx);
        }
        if (kTargets[Index].probe == Probe::poolc4) {
            emit_poolc4(kTargets[Index].name, "enter", call, rcx);
        }
        if (kTargets[Index].probe == Probe::c4query) {
            emit_c4query(kTargets[Index].name, call, rcx, rdx);
        }
    }
    // TIME-based, not count-based. p2-145 fired the census every 64 GLOBAL calls while
    // auth_a alone ran 928,227 times - ~14,000 censuses x 31 targets, which is the 51MB mac
    // log and the 155MB rig log. A wall-clock floor makes the census independent of how hot
    // the busiest target happens to be.
    if (total % kCensusInterval == 0) {
        const std::uint64_t now = GetTickCount64();
        const std::uint64_t last = g_lastCensusMs.load(std::memory_order_relaxed);
        if (now - last >= kCensusMinIntervalMs) {
            g_lastCensusMs.store(now, std::memory_order_relaxed);
            emit_summary("periodic");
        }
    }
    const auto original = reinterpret_cast<AnyFn>(g_handles[Index].original);
    const std::uint64_t result = original(rcx, rdx, r8, r9, a5, a6, a7, a8, a9, a10,
                                          a11, a12, a13, a14, a15, a16, a17, a18, a19, a20);
    // The LEAVE probe is what turns a snapshot into a measurement: `fill` either moved
    // supply into mgr+0xC118 across this call or it did not, and the delta says which.
    if (siteMatch) {
        run_probe(Index, kTargets[Index].probe, kTargets[Index].name, "leave", call, rcx);
        if (kTargets[Index].probe == Probe::resvtable) {
            emit_resvtable(Index, kTargets[Index].name, call);
        }
        if (kTargets[Index].probe == Probe::pubrest) {
            emit_pubrest(Index, kTargets[Index].name, "leave", call, callerRva,
                         rcx, rdx, r8);
        }
        if (kTargets[Index].probe == Probe::poolc4) {
            // The LEAVE side is the measurement: same array, after the handler ran.
            emit_poolc4(kTargets[Index].name, "leave", call, rcx);
        }
        if (kTargets[Index].probe == Probe::retwatch
            || kTargets[Index].probe == Probe::c4query) {
            emit_retwatch(Index, kTargets[Index].name, call, result);
        }
        if (kTargets[Index].probe == Probe::member) {
            emit_member_probe(kTargets[Index].name, call, result);
        }
        if (kTargets[Index].probe == Probe::retidx) {
            emit_retidx(kTargets[Index].name, call, result);
        }
        if (kTargets[Index].probe == Probe::registry) {
            // The count DELTA across the call is the proof that registration happened.
            emit_registry(kTargets[Index].name, "leave", call, rcx);
        }
    }
    const void* const outPtr = (kTargets[Index].out_param == OutParam::rdx)   ? rdx
                             : (kTargets[Index].out_param == OutParam::rcx)   ? rcx
                                                                              : nullptr;
    // A GUARD, not a nicety: an out-pointer that is null, in the first page, or not
    // 4-byte aligned is a mis-declared register, not a real pointer. Dereferencing one
    // inside a detour froze the client once; refuse instead, and say so in the log.
    const bool outUsable = outPtr != nullptr
                           && reinterpret_cast<std::uintptr_t>(outPtr) >= 0x10000U
                           && (reinterpret_cast<std::uintptr_t>(outPtr) & 3U) == 0U;
    if (detail && kTargets[Index].out_param != OutParam::none && !outUsable) {
        std::array<char, 160> text{};
        const int written = std::snprintf(
            text.data(), text.size(),
            "ev=mtrace stage=outparam fn=%s call=%llu result=refused why=not-a-pointer ptr=0x%llX",
            kTargets[Index].name, static_cast<unsigned long long>(call),
            reinterpret_cast<unsigned long long>(outPtr));
        if (written > 0) {
            emit(text.data(), static_cast<std::size_t>(written));
        }
    }
    if (detail && outUsable) {
        // idx_alloc writes its verdict THROUGH its out-pointer and returns the pointer
        // itself (20.216 R4) - rax alone cannot separate success from -1.
        const auto* out = static_cast<const std::uint64_t*>(outPtr);
        std::array<char, 144> text{};
        const int written = std::snprintf(
            text.data(), text.size(),
            "ev=mtrace stage=outparam fn=%s call=%llu out0=0x%llX out1=0x%llX",
            kTargets[Index].name, static_cast<unsigned long long>(call),
            static_cast<unsigned long long>(out[0]),
            static_cast<unsigned long long>(out[1]));
        if (written > 0) {
            emit(text.data(), static_cast<std::size_t>(written));
        }
    }
    // Leave visibility: the flat budget for the burst, THEN first-seen (slot, ret-class)
    // keys - a new bail class or a new slot can never be silenced by an exhausted budget
    // (the p2-164 lesson: 898 calls, 24 logged, the entire peer era invisible).
    bool leaveVisible = detail;
    const unsigned leaveClass = classify_ret(result);
    if (!leaveVisible && kTargets[Index].first_seen_leave) {
        const std::uint64_t leaveKey =
            (reinterpret_cast<std::uint64_t>(rdx) << 4U)
            | static_cast<std::uint64_t>(leaveClass);
        leaveVisible = leave_key_first_seen(Index, leaveKey);
    }
    if (leaveVisible) {
        std::array<char, 160> text{};
        const int written = std::snprintf(text.data(), text.size(),
                                          "ev=mtrace stage=leave fn=%s call=%llu ret=0x%llX "
                                          "slot=0x%llX retcls=%u%s",
                                          kTargets[Index].name,
                                          static_cast<unsigned long long>(call),
                                          static_cast<unsigned long long>(result),
                                          reinterpret_cast<unsigned long long>(rdx),
                                          leaveClass,
                                          detail ? "" : " note=first-seen-key");
        if (written > 0) {
            emit(text.data(), static_cast<std::size_t>(written));
        }
    }
    return result;
}

/** Prints every target's call count, ZEROS INCLUDED. This is the whole point. */
void emit_summary(const char* reason) noexcept {
    for (std::size_t i = 0; i < kTargets.size(); ++i) {
        std::array<char, 160> text{};
        const int written = std::snprintf(
            text.data(), text.size(),
            "ev=mtrace stage=census why=%s fn=%s rva=0x%llX attached=%u calls=%llu",
            reason, kTargets[i].name, static_cast<unsigned long long>(kTargets[i].rva),
            g_handles[i].attached ? 1U : 0U,
            static_cast<unsigned long long>(g_calls[i].load(std::memory_order_relaxed)));
        if (written > 0) {
            emit(text.data(), static_cast<std::size_t>(written));
        }
    }
}

/**
 * Reads the two pool schema-key descriptors and prints their keys. UNCONDITIONAL: it
 * depends on no message arriving and no hook firing, so its absence from a log proves the
 * build is stale rather than that the client lacked the behaviour (the p2-144 brief's
 * ABSENCE NEGATIVE, and the reason this boot cannot be wasted by the creation flake).
 *
 * The type-30 key is independently known to be 0x80808683, so this instrument carries its
 * own oracle: if type30 does not match, the reading method is wrong and the type-28 value
 * printed beside it MUST be discarded rather than used to build a message.
 *
 * Both descriptors sit past .data's raw-backed extent - zero on disk, registered at
 * runtime - which is exactly why they cannot be read offline.
 */
void emit_schema_keys() noexcept {
    const auto read_key = [](std::uintptr_t rva) noexcept -> std::uint32_t {
        const auto* const slot = reinterpret_cast<void* const*>(g_base + rva);
        if (slot == nullptr || *slot == nullptr) {
            return 0U;
        }
        return *static_cast<const std::uint32_t*>(*slot);
    };
    const std::uint32_t key28 = read_key(kType28SchemaKeyPtr);
    const std::uint32_t key30 = read_key(kType30SchemaKeyPtr);
    std::array<char, 224> text{};
    const int written = std::snprintf(
        text.data(), text.size(),
        "ev=mtrace stage=schemakey type28=0x%08X type30=0x%08X oracle=0x%08X verdict=%s",
        key28, key30, kType30SchemaKeyOracle,
        (key30 == kType30SchemaKeyOracle) ? "ok" : "MISMATCH-DISCARD-TYPE28");
    if (written > 0) {
        emit(text.data(), static_cast<std::size_t>(written));
    }
}

template <std::size_t... Index>
void install_all(std::index_sequence<Index...>) noexcept {
    (
        [] {
            constexpr std::size_t i = Index;
            // The notifier detour is per-machine opt-in (WIDE NET directive, p2-164
            // attempt 1): the body is obfuscated and a rig login failure correlated
            // with its attachment, so it only arms when the setting names it.
            if constexpr (kTargets[i].rva == kResvNotifyRva) {
                if (!core::settings::get().client.notifierHook) {
                    return;
                }
            }
            const auto address = reinterpret_cast<void*>(g_base + kTargets[i].rva);
            diagnostics::ModuleRange range{};
            if (!diagnostics::module_range(reinterpret_cast<HMODULE>(g_base), range)
                || !diagnostics::contains(range, g_base + kTargets[i].rva)) {
                return;
            }
            const hooking::detour::Spec spec{address, reinterpret_cast<void*>(&observe<i>)};
            (void)hooking::detour::install(spec, g_handles[i]);
        }(),
        ...);
}

} // namespace

bool install() noexcept {
    if (!core::settings::get().client.milestoneTrace) {
        emit("ev=mtrace stage=install result=skipped why=disarmed", 51);
        return true;
    }
    if (g_installed.exchange(true, std::memory_order_relaxed)) {
        return true;
    }
    std::byte* const base = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    if (base == nullptr) {
        emit("ev=mtrace stage=install result=fail why=base", 44);
        return false;
    }
    g_base = reinterpret_cast<std::uintptr_t>(base);
    emit_schema_keys();
    install_all(std::make_index_sequence<kTargets.size()>{});
    // The install census states which detours actually attached, so a later zero can be
    // read as "never called" rather than "never hooked".
    emit_summary("install");
    // THE cond5 WIRE-WATCH (20.251): hardware write-watches on the participant gate
    // bytes. Installs its own VEC + watchdog; arms itself off the ptable probe above.
    // No new detours, no game-memory writes - the crash-safety argument is in
    // gate_wwatch.cpp's header comment, and the boot brief carries the short form.
    (void)gate_wwatch::install();
    return true;
}

bool uninstall() noexcept {
    bool ok = true;
    for (auto& handle : g_handles) {
        if (handle.attached) {
            ok = hooking::detour::uninstall(handle) && ok;
        }
    }
    g_installed.store(false, std::memory_order_relaxed);
    return ok;
}

bool is_installed() noexcept {
    for (const auto& handle : g_handles) {
        if (handle.attached) {
            return true;
        }
    }
    return false;
}

} // namespace sunrise::client::hooks::milestone_trace
