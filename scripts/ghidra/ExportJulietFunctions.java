// Export all Juliet present/not_observed functions from one offline object.
// Arguments: <output-directory>

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class ExportJulietFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("expected one output directory");
        }

        Path outputDirectory = Paths.get(args[0]);
        Files.createDirectories(outputDirectory);
        Path manifest = outputDirectory.resolve("functions.tsv");
        FunctionManager manager = currentProgram.getFunctionManager();
        List<Function> selected = new ArrayList<>();
        for (Function function : manager.getFunctions(true)) {
            if (labelFor(function.getName()) != null) {
                selected.add(function);
            }
        }
        selected.sort(
            Comparator.comparing(function -> function.getName(true))
        );

        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("failed to open program");
        }
        List<String> rows = new ArrayList<>();
        rows.add("label\tfull_name\toutput_file\tcompleted");
        try {
            int index = 0;
            for (Function function : selected) {
                String label = labelFor(function.getName());
                String fullName = function.getName(true);
                String fileName = String.format(
                    "%02d-%s-%s.c",
                    index,
                    label,
                    sanitize(fullName)
                );
                DecompileResults result = decompiler.decompileFunction(
                    function, 120, monitor
                );
                boolean completed = result.decompileCompleted();
                if (completed) {
                    Files.writeString(
                        outputDirectory.resolve(fileName),
                        result.getDecompiledFunction().getC(),
                        StandardCharsets.UTF_8
                    );
                }
                rows.add(
                    label
                        + "\t"
                        + sanitizeField(fullName)
                        + "\t"
                        + fileName
                        + "\t"
                        + completed
                );
                index++;
            }
        }
        finally {
            decompiler.dispose();
        }
        Files.write(
            manifest,
            rows,
            StandardCharsets.UTF_8
        );
        println("EXPORTED_JULIET_FUNCTIONS " + (rows.size() - 1));
    }

    private String labelFor(String name) {
        if (
            name.equals("bad")
                || name.endsWith("_bad")
                || name.startsWith("bad")
        ) {
            return "present";
        }
        if (
            name.equals("good")
                || name.endsWith("_good")
                || name.startsWith("good")
        ) {
            return "not_observed";
        }
        return null;
    }

    private String sanitize(String value) {
        return value.replaceAll("[^A-Za-z0-9_.-]", "_");
    }

    private String sanitizeField(String value) {
        return value.replace('\t', ' ').replace('\n', ' ');
    }
}
