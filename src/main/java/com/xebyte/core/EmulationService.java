package com.xebyte.core;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.Register;
import java.math.BigInteger;
import java.util.*;

/**
 * MCP endpoints for targeted function emulation via Ghidra's P-code emulator.
 *
 * <p>Designed for API hash resolution: emulate a hash function with controlled
 * inputs (candidate API name string in memory, hash parameters in registers)
 * and read the computed hash from the output register. No full process needed —
 * the emulator runs the function's P-code in isolation.</p>
 *
 * <h3>Typical agent workflow for API hash resolution</h3>
 * <pre>{@code
 * 1. decompile_function(hash_func_addr) → understand calling convention
 * 2. get_function_variables(hash_func) → identify input/output registers
 * 3. emulate_function(hash_func_addr, registers={x0: string_ptr},
 *        memory=[{addr: string_ptr, data: "CreateProcessW\0"}])
 *    → returns {x0: 0x7C0DFCAA}
 * 4. Compare 0x7C0DFCAA against target hash → match!
 * 5. batch_set_comments(hash_call_addr, "Resolved: CreateProcessW")
 * }</pre>
 *
 * <h3>Batch mode for brute-forcing</h3>
 * <pre>{@code
 * emulate_hash_batch(hash_func_addr, register_template={x0: "${STRING_PTR}"},
 *     candidates=["CreateProcessW", "VirtualAlloc", "LoadLibraryA", ...],
 *     target_hash=0x7C0DFCAA, result_register="x0")
 *   → returns {matched: "CreateProcessW", hash: 0x7C0DFCAA, iterations: 42}
 * }</pre>
 *
 * @since 5.4.0
 */
@McpToolGroup(value = "emulation",
        description = "Targeted function emulation for hash resolution, crypto analysis, " +
                "and controlled execution of isolated code paths")
public class EmulationService {

    private static final int DEFAULT_TIMEOUT_MS = 10_000;
    private static final int DEFAULT_MAX_STEPS = 10_000;
    private static final int MAX_STEPS = 100_000;
    private static final int MAX_CANDIDATES = 10_000;
    private static final long STACK_BASE = 0x7FFF0000L;
    // AArch64 PC values must be 4-byte aligned.
    private static final long RETURN_SENTINEL = 0x7FFF1000L;
    // Scratch memory for writing candidate strings during emulation
    private static final long SCRATCH_BASE = 0x7FFE0000L;
    private static final int SCRATCH_SIZE = 0x10000;

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public EmulationService(ProgramProvider programProvider,
                            ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    // ========================================================================
    // Single-function emulation
    // ========================================================================

    /**
     * Emulate a function with controlled inputs and return the final state.
     *
     * <p>Sets up the P-code emulator with the specified register values and
     * memory contents, runs the function until RET or step limit, and returns
     * all register values at completion.</p>
     */
    @McpTool(path = "/emulate_function", method = "POST",
            description = "Emulate a single function with controlled register/memory inputs. " +
                    "Returns final register state after execution. Ideal for understanding " +
                    "hash functions, crypto routines, or any pure-computation code path.",
            category = "emulation")
    public Response emulateFunction(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                    description = "Entry point address of the function to emulate") String addressStr,
            @Param(value = "registers", source = ParamSource.BODY, fieldsJson = true,
                    description = "Initial register values as JSON: {\"x0\": \"0x1234\", \"x1\": \"0x7FFE0000\"}") String registersJson,
            @Param(value = "memory", source = ParamSource.BODY, fieldsJson = true,
                    description = "Memory regions to pre-populate as JSON array: [{\"address\": \"0x7FFE0000\", \"data\": \"base64...\"}] " +
                            "or [{\"address\": \"0x7FFE0000\", \"string\": \"CreateProcessW\\u0000\"}]") String memoryJson,
            @Param(value = "max_steps", source = ParamSource.BODY, defaultValue = "10000",
                    description = "Maximum P-code steps before timeout") int maxSteps,
            @Param(value = "return_registers", source = ParamSource.BODY, defaultValue = "",
                    description = "Comma-separated register names to return (empty = all general-purpose)") String returnRegisters,
            @Param(value = "read_memory_after", source = ParamSource.BODY, fieldsJson = true,
                    defaultValue = "",
                    description = "Memory regions to read back AFTER emulation, as a JSON array: " +
                            "[{\"address\": \"0x408300\", \"length\": 16}, ...]. Needed to observe " +
                            "in-place mutations (e.g. a function that lowercases a string via a " +
                            "pointer argument) -- the emulator's memory is an ISOLATED overlay and " +
                            "never touches the real program, so a plain read_memory call after " +
                            "emulation sees only the ORIGINAL unmodified bytes, not the emulated " +
                            "result. This reads from the emulator's own state instead.")
                    String readMemoryAfterJson,
            @Param(value = "program", defaultValue = "") String programName) {

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Address entryAddr = ServiceUtils.parseAddress(program, addressStr);
        if (entryAddr == null) return Response.err(ServiceUtils.getLastParseError());

        Function func = program.getFunctionManager().getFunctionAt(entryAddr);
        if (func == null) return Response.err("No function at address: " + addressStr);

        try {
            EmulatorHelper emu = new EmulatorHelper(program);
            try {

                // Apply user-specified register values
                if (registersJson != null && !registersJson.isEmpty()) {
                    Map<String, Object> regs = JsonHelper.parseJson(registersJson);
                    for (Map.Entry<String, Object> entry : regs.entrySet()) {
                        String regName = entry.getKey();
                        long value = parseLongValue(String.valueOf(entry.getValue()));
                        emu.writeRegister(regName, value);
                    }
                }

                // Apply user-specified memory contents
                if (memoryJson != null && !memoryJson.isEmpty()) {
                    List<Map<String, String>> regions = ServiceUtils.convertToMapList(
                            JsonHelper.parseJson(memoryJson).get("regions"));
                    if (regions == null) {
                        // Try parsing as a direct array
                        regions = ServiceUtils.convertToMapList(memoryJson);
                    }
                    if (regions != null) {
                        for (Map<String, String> region : regions) {
                            String addrStr = String.valueOf(region.get("address"));
                            Address memAddr = ServiceUtils.parseAddress(program, addrStr);
                            if (memAddr == null) continue;

                            if (region.containsKey("string")) {
                                // Write a null-terminated string
                                String str = String.valueOf(region.get("string"));
                                byte[] strBytes = (str + "\0").getBytes("UTF-8");
                                emu.writeMemory(memAddr, strBytes);
                            } else if (region.containsKey("data")) {
                                // Write base64-encoded bytes
                                String b64 = String.valueOf(region.get("data"));
                                byte[] data = Base64.getDecoder().decode(b64);
                                emu.writeMemory(memAddr, data);
                            } else if (region.containsKey("hex")) {
                                // Write hex-encoded bytes
                                String hex = String.valueOf(region.get("hex"));
                                byte[] data = hexToBytes(hex);
                                emu.writeMemory(memAddr, data);
                            }
                        }
                    }
                }

                // Install the architecture-specific frame after caller-supplied
                // registers so SP/FP/LR remain valid for return detection.
                setupEmulationFrame(program, emu);
                // Run emulation with a hard step bound. emu.run(...) is
                // unbounded — it loops until a breakpoint or fault — so a
                // target with an infinite loop (or one that never executes
                // RET to hit the returnSentinel) would hang the HTTP
                // handler thread forever. Step explicitly so the advertised
                // max_steps parameter is actually honored.
                int effectiveMaxSteps = Math.min(
                        maxSteps > 0 ? maxSteps : DEFAULT_MAX_STEPS, MAX_STEPS);
                ghidra.util.task.TaskMonitor monitor =
                        new ghidra.util.task.ConsoleTaskMonitor();

                // Position PC at the entry point, then step.
                emu.writeRegister(emu.getPCRegister(), entryAddr.getOffset());

                int steps = 0;
                boolean success = true;
                boolean hitReturn = false;
                String stopReason = "max_steps_exceeded";
                Address pc = null;
                while (steps < effectiveMaxSteps) {
                    steps++;
                    if (!emu.step(monitor)) {
                        success = false;
                        stopReason = "fault: " + emu.getLastError();
                        break;
                    }
                    pc = emu.getExecutionAddress();
                    if (pc != null && pc.getOffset() == RETURN_SENTINEL) {
                        hitReturn = true;
                        stopReason = "return";
                        break;
                    }
                }
                if (steps >= effectiveMaxSteps && !hitReturn && success) {
                    // Step cap reached without RET or fault — likely an
                    // infinite loop or a path that never returns.
                    success = false;
                }

                // Collect results
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", success);
                result.put("function", func.getName());
                result.put("entry_address", entryAddr.toString());
                result.put("steps_executed", steps);
                result.put("max_steps", effectiveMaxSteps);
                result.put("stop_reason", stopReason);

                pc = emu.getExecutionAddress();
                result.put("final_pc", pc != null ? pc.toString() : "unknown");
                result.put("hit_return", hitReturn);

                // Read registers
                Map<String, String> regValues = new LinkedHashMap<>();
                if (returnRegisters != null && !returnRegisters.isEmpty()) {
                    for (String rn : returnRegisters.split(",")) {
                        rn = rn.trim();
                        try {
                            BigInteger val = emu.readRegister(rn);
                            regValues.put(rn, "0x" + val.toString(16));
                        } catch (Exception e) {
                            regValues.put(rn, "error: " + e.getMessage());
                        }
                    }
                } else {
                    // Return common general-purpose registers for this language.
                    for (String rn : defaultGeneralPurposeRegisters(program)) {
                        try {
                            BigInteger val = emu.readRegister(rn);
                            regValues.put(rn, "0x" + val.toString(16));
                        } catch (Exception ignored) {
                            // Register may not exist for this architecture
                        }
                    }
                }
                result.put("registers", regValues);

                // Read back caller-specified memory regions from the EMULATOR's
                // state (not the program's), so a mutation made only inside the
                // sandboxed run -- e.g. a string lowercased in place via a
                // pointer argument -- is observable. Read even on a fault or
                // step-limit exit: a partial mutation up to the point of failure
                // is still useful evidence for a caller diagnosing why two
                // implementations disagree.
                if (readMemoryAfterJson != null && !readMemoryAfterJson.isEmpty()) {
                    List<Map<String, String>> regions = ServiceUtils.convertToMapList(
                            JsonHelper.parseJson(readMemoryAfterJson).get("regions"));
                    if (regions == null) {
                        regions = ServiceUtils.convertToMapList(readMemoryAfterJson);
                    }
                    if (regions != null) {
                        List<Map<String, Object>> memResults = new ArrayList<>();
                        for (Map<String, String> region : regions) {
                            String addrStr = String.valueOf(region.get("address"));
                            Map<String, Object> entry = new LinkedHashMap<>();
                            entry.put("address", addrStr);
                            Address memAddr = ServiceUtils.parseAddress(program, addrStr);
                            // Gson parses JSON numbers as Double, so a naive
                            // Integer.decode(String.valueOf(...)) sees "16.0"
                            // and throws -- JsonHelper.getInt already exists
                            // to handle Double/Integer/Long/String uniformly.
                            int length = JsonHelper.getInt(region.get("length"), 0);
                            if (memAddr == null || length <= 0) {
                                entry.put("error", "invalid address or length");
                            } else {
                                try {
                                    byte[] readBack = emu.readMemory(memAddr, length);
                                    StringBuilder hex = new StringBuilder(readBack.length * 2);
                                    for (byte b : readBack) {
                                        hex.append(String.format("%02x", b));
                                    }
                                    entry.put("hex", hex.toString());
                                } catch (Exception e) {
                                    entry.put("error", e.getMessage());
                                }
                            }
                            memResults.add(entry);
                        }
                        result.put("memory", memResults);
                    }
                }

                String lastError = emu.getLastError();
                if (lastError != null && !lastError.isEmpty()) {
                    result.put("emulation_error", lastError);
                }

                return Response.ok(result);
            } finally {
                emu.dispose();
            }
        } catch (Exception e) {
            return Response.err("Emulation failed: " + e.getMessage());
        }
    }

    // ========================================================================
    // Batch hash resolution
    // ========================================================================

    /**
     * Brute-force API hash resolution by emulating a hash function with
     * a list of candidate API name strings.
     *
     * <p>For each candidate, writes the string to scratch memory, sets the
     * string pointer register, emulates the hash function, reads the result
     * register, and compares against the target hash. Stops on first match
     * or after exhausting all candidates.</p>
     */
    @McpTool(path = "/emulate_hash_batch", method = "POST",
            description = "Brute-force API hash resolution. Emulates a hash function with " +
                    "each candidate API name and returns the one that produces the target hash. " +
                    "Ideal for resolving ROR13, CRC32, djb2, FNV, and custom hash algorithms.",
            category = "emulation")
    public Response emulateHashBatch(
            @Param(value = "hash_function_address", paramType = "address", source = ParamSource.BODY,
                    description = "Address of the hash computation function") String hashFuncAddr,
            @Param(value = "string_register", source = ParamSource.BODY,
                    description = "Register that receives the pointer to the API name string (e.g., x0, x1, RCX)") String stringRegister,
            @Param(value = "result_register", source = ParamSource.BODY, defaultValue = "",
                    description = "Register containing the computed hash (defaults to x0 on AArch64, EAX otherwise)") String resultRegister,
            @Param(value = "target_hash", source = ParamSource.BODY,
                    description = "Target hash value to match (hex string like 0x7C0DFCAA)") String targetHashStr,
            @Param(value = "candidates", source = ParamSource.BODY, fieldsJson = true,
                    description = "JSON array of candidate API name strings: [\"CreateProcessW\", \"VirtualAlloc\", ...]") String candidatesJson,
            @Param(value = "initial_registers", source = ParamSource.BODY, fieldsJson = true, defaultValue = "",
                    description = "Additional register values to set before each emulation (JSON object)") String initialRegistersJson,
            @Param(value = "wide_string", source = ParamSource.BODY, defaultValue = "false",
                    description = "Write candidate strings as UTF-16LE (wide) instead of ASCII") boolean wideString,
            @Param(value = "program", defaultValue = "") String programName) {

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Address entryAddr = ServiceUtils.parseAddress(program, hashFuncAddr);
        if (entryAddr == null) return Response.err(ServiceUtils.getLastParseError());

        Function func = program.getFunctionManager().getFunctionAt(entryAddr);
        if (func == null) return Response.err("No function at address: " + hashFuncAddr);
        if (resultRegister == null || resultRegister.isBlank()) {
            resultRegister = isAarch64(program) ? "x0" : "EAX";
        }

        long targetHash;
        try {
            targetHash = parseLongValue(targetHashStr);
        } catch (Exception e) {
            return Response.err("Invalid target_hash: " + targetHashStr);
        }

        // Parse candidates
        List<String> candidates = new ArrayList<>();
        if (candidatesJson != null && !candidatesJson.isEmpty()) {
            try {
                Object parsed = JsonHelper.parseJson("{\"c\":" + candidatesJson + "}").get("c");
                if (parsed instanceof List<?> list) {
                    for (Object item : list) {
                        candidates.add(String.valueOf(item));
                    }
                }
            } catch (Exception e) {
                return Response.err("Invalid candidates JSON: " + e.getMessage());
            }
        }
        if (candidates.isEmpty()) {
            return Response.err("No candidates provided");
        }
        if (candidates.size() > MAX_CANDIDATES) {
            return Response.err("Too many candidates (max " + MAX_CANDIDATES + ")");
        }

        // Parse additional registers
        Map<String, Long> extraRegs = new LinkedHashMap<>();
        if (initialRegistersJson != null && !initialRegistersJson.isEmpty()) {
            Map<String, Object> parsed = JsonHelper.parseJson(initialRegistersJson);
            for (Map.Entry<String, Object> entry : parsed.entrySet()) {
                extraRegs.put(entry.getKey(), parseLongValue(String.valueOf(entry.getValue())));
            }
        }

        try {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("function", func.getName());
            result.put("target_hash", "0x" + Long.toHexString(targetHash));
            result.put("total_candidates", candidates.size());

            Address scratchAddr = program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(SCRATCH_BASE);
            Address returnAddr = program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(RETURN_SENTINEL);

            List<Map<String, String>> matches = new ArrayList<>();
            int tested = 0;

            for (String candidate : candidates) {
                tested++;
                EmulatorHelper emu = new EmulatorHelper(program);
                try {

                    // Write candidate string to scratch memory
                    byte[] strBytes;
                    if (wideString) {
                        strBytes = (candidate + "\0").getBytes("UTF-16LE");
                    } else {
                        strBytes = (candidate + "\0").getBytes("US-ASCII");
                    }
                    emu.writeMemory(scratchAddr, strBytes);

                    // Set string pointer register
                    emu.writeRegister(stringRegister, SCRATCH_BASE);

                    // Set additional registers
                    for (Map.Entry<String, Long> entry : extraRegs.entrySet()) {
                        emu.writeRegister(entry.getKey(), entry.getValue());
                    }

                    // Initialize the architecture-specific frame after the
                    // caller-supplied register values are installed.
                    setupEmulationFrame(program, emu);
                    // Set breakpoint at return sentinel
                    emu.setBreakpoint(returnAddr);

                    // Run
                    emu.run(entryAddr, null, new ghidra.util.task.ConsoleTaskMonitor());

                    // Read result register
                    BigInteger hashResult = emu.readRegister(resultRegister);
                    long computedHash = hashResult.longValue() & 0xFFFFFFFFL; // mask to 32-bit

                    if (computedHash == (targetHash & 0xFFFFFFFFL)) {
                        Map<String, String> match = new LinkedHashMap<>();
                        match.put("api_name", candidate);
                        match.put("computed_hash", "0x" + Long.toHexString(computedHash));
                        match.put("iteration", String.valueOf(tested));
                        matches.add(match);
                        // Continue to find ALL matches (some hash functions have collisions)
                    }
                } finally {
                    emu.dispose();
                }
            }

            result.put("tested", tested);
            result.put("matches", matches);
            result.put("resolved", !matches.isEmpty());
            if (!matches.isEmpty()) {
                result.put("best_match", matches.get(0).get("api_name"));
            }

            return Response.ok(result);
        } catch (Exception e) {
            return Response.err("Batch emulation failed: " + e.getMessage());
        }
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    private static boolean isAarch64(Program program) {
        String processor = program.getLanguage().getProcessor().toString();
        String languageId = program.getLanguage().getLanguageID().getIdAsString();
        return "AARCH64".equalsIgnoreCase(processor) ||
                languageId.regionMatches(true, 0, "AARCH64:", 0, 8);
    }

    private static String findRegister(
            Program program,
            String... candidates) {

        for (String candidate : candidates) {
            if (candidate != null &&
                    program.getRegister(candidate) != null) {
                return candidate;
            }
        }
        return null;
    }

    private static void setupEmulationFrame(
            Program program,
            EmulatorHelper emu) throws Exception {

        AddressSpace stackSpace =
                program.getCompilerSpec().getStackBaseSpace();
        Address stackAddress = stackSpace.getAddress(STACK_BASE);

        Register stackPointer = emu.getStackPointerRegister();
        emu.writeRegister(stackPointer, stackAddress.getOffset());

        String framePointer = findRegister(
                program, "x29", "X29", "fp", "FP", "RBP", "EBP");
        if (framePointer != null) {
            emu.writeRegister(framePointer, stackAddress.getOffset());
        }

        // AArch64 RET uses X30/LR. Stack-return architectures use [SP].
        String linkRegister = findRegister(
                program, "x30", "X30", "lr", "LR", "r30", "R30");
        if (linkRegister != null) {
            emu.writeRegister(linkRegister, RETURN_SENTINEL);
        }
        else {
            emu.writeStackValue(
                    0,
                    stackSpace.getPointerSize(),
                    RETURN_SENTINEL);
        }
    }

    private static List<String> defaultGeneralPurposeRegisters(
            Program program) {

        List<String> registers = new ArrayList<>();
        if (isAarch64(program)) {
            for (int i = 0; i <= 30; i++) {
                registers.add("x" + i);
            }
            registers.add("sp");
            registers.add("pc");
        }
        else {
            Collections.addAll(
                    registers,
                    "EAX", "EBX", "ECX", "EDX",
                    "ESI", "EDI", "ESP", "EBP", "EIP");
        }
        return registers;
    }
    private static long parseLongValue(String s) {
        if (s == null || s.isEmpty()) return 0;
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) {
            return Long.parseUnsignedLong(s.substring(2), 16);
        }
        return Long.parseLong(s);
    }

    private static byte[] hexToBytes(String hex) {
        hex = hex.replace(" ", "").replace("0x", "");
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}
