// Ghidra headless post-script used by scripts/audit/reverse_tooling.py.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;

import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ExportCallGraph extends GhidraScript {
    private static String jsonEscape(String value) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '\\':
                    builder.append("\\\\");
                    break;
                case '"':
                    builder.append("\\\"");
                    break;
                case '\n':
                    builder.append("\\n");
                    break;
                case '\r':
                    builder.append("\\r");
                    break;
                case '\t':
                    builder.append("\\t");
                    break;
                default:
                    if (ch < 0x20) {
                        builder.append(String.format("\\u%04x", (int) ch));
                    } else {
                        builder.append(ch);
                    }
            }
        }
        return builder.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("output JSON path argument is required");
        }

        List<String> functions = new ArrayList<>();
        List<String> edges = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext() && !monitor.isCancelled()) {
            Function caller = iterator.next();
            String callerName = caller.getName(true);
            functions.add(callerName);

            InstructionIterator instructions = currentProgram.getListing().getInstructions(caller.getBody(), true);
            while (instructions.hasNext() && !monitor.isCancelled()) {
                Instruction instruction = instructions.next();
                for (Reference reference : instruction.getReferencesFrom()) {
                    if (!reference.getReferenceType().isCall()) {
                        continue;
                    }
                    Function callee = currentProgram.getFunctionManager().getFunctionAt(reference.getToAddress());
                    String calleeName = callee == null ? reference.getToAddress().toString() : callee.getName(true);
                    edges.add("{\"caller\":\"" + jsonEscape(callerName) + "\",\"callee\":\"" + jsonEscape(calleeName) + "\"}");
                }
            }
        }

        Collections.sort(functions);
        Collections.sort(edges);
        try (FileWriter writer = new FileWriter(args[0])) {
            writer.write("{\"functions\":[");
            for (int i = 0; i < functions.size(); i++) {
                if (i > 0) {
                    writer.write(",");
                }
                writer.write("\"" + jsonEscape(functions.get(i)) + "\"");
            }
            writer.write("],\"edges\":[");
            for (int i = 0; i < edges.size(); i++) {
                if (i > 0) {
                    writer.write(",");
                }
                writer.write(edges.get(i));
            }
            writer.write("]}");
        }
    }
}
