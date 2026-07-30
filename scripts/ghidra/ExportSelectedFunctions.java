// Export selected functions as pseudo-C files during an offline headless run.
// Arguments: <output-directory> <function-name> [<function-name> ...]

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class ExportSelectedFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "expected output directory and at least one function name"
            );
        }

        Path outputDirectory = Paths.get(args[0]);
        Files.createDirectories(outputDirectory);
        FunctionManager functionManager = currentProgram.getFunctionManager();
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("failed to open program in decompiler");
        }

        try {
            for (int index = 1; index < args.length; index++) {
                String requestedName = args[index];
                Function function = findFunction(functionManager, requestedName);
                if (function == null) {
                    throw new IllegalStateException(
                        "function not found: " + requestedName
                    );
                }
                DecompileResults results = decompiler.decompileFunction(
                    function, 120, monitor
                );
                if (!results.decompileCompleted()) {
                    throw new IllegalStateException(
                        "decompilation failed for "
                            + requestedName
                            + ": "
                            + results.getErrorMessage()
                    );
                }
                String pseudoC = results.getDecompiledFunction().getC();
                Path output = outputDirectory.resolve(
                    sanitize(requestedName) + ".c"
                );
                Files.writeString(
                    output,
                    pseudoC,
                    StandardCharsets.UTF_8
                );
                println("EXPORTED " + requestedName + " -> " + output);
            }
        }
        finally {
            decompiler.dispose();
        }
    }

    private Function findFunction(
        FunctionManager functionManager,
        String requestedName
    ) {
        for (Function function : functionManager.getFunctions(true)) {
            if (function.getName().equals(requestedName)) {
                return function;
            }
        }
        return null;
    }

    private String sanitize(String value) {
        return value.replaceAll("[^A-Za-z0-9_.-]", "_");
    }
}
