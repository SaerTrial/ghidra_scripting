//Fina all unconditional backward jumps. Ghira 11.0.3
//@author: Huang 
//@category ARM
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.protorules.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.data.ISF.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.util.ArrayList;

public class FindBackwardUnconditionalJumps_NoBookmarks extends GhidraScript {

	private static class Finding {
        Address instrAddr;
        String instrText;
        Address targetAddr;
        long delta;
        Finding(Address a, String t, Address tgt, long d) {
            instrAddr = a; instrText = t; targetAddr = tgt; delta = d;
        }
    }

    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        println("Scanning for backward unconditional jumps in: " + currentProgram.getName());

        
	ArrayList<Finding> findings = new ArrayList<Finding>();
        InstructionIterator it = listing.getInstructions(true);

        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction instr = it.next();
            FlowType ft = instr.getFlowType();
            if (ft == null) continue;

            // Keep unconditional *jumps* (exclude calls/returns)
            if (ft.isUnConditional() && ft.isJump()) {
                Address[] flows = instr.getFlows();
                if (flows == null || flows.length == 0) {
                    // Likely an indirect jump; ignore in this simple version
                    continue;
                }
                for (Address tgt : flows) {
                    if (tgt == null) continue;
                    if (tgt.compareTo(instr.getAddress()) < 0) { // backward edge
                        long delta = tgt.getOffset() - instr.getAddress().getOffset(); // negative
                        findings.add(new Finding(instr.getAddress(), instr.toString(), tgt, delta));
                    }
                }
            }
        }

        // Print results
        if (findings.isEmpty()) {
            println("No backward unconditional jumps found.");
            return;
        }

        println(String.format("Found %d backward unconditional jump(s):", findings.size()));
        println(String.format("%-12s  %-44s  %-12s  %s", "Addr", "Instruction", "Target", "Delta"));
        println("--------------------------------------------------------------------------------------------");
        for (Finding f : findings) {
            println(String.format("%-12s  %-44s  %-12s  %+d",
                f.instrAddr.toString(),
                truncate(f.instrText, 44),
                f.targetAddr.toString(),
                f.delta));
        }
    }

 private String truncate(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        return s.substring(0, Math.max(0, max - 3)) + "...";
    }

}
