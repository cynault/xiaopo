import ghidra.app.script.GhidraScript;
import ghidra.app.services.BlockModelService;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Set;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;

public class DataFlowAnalysis extends GhidraScript {
    public void run() throws Exception {
        // 初始化输入参数
        InputParameter inputParameter = initInput();
        // 数据流分析
        // ArrayList<Path> Paths = 
        dataFlowAnalysis(inputParameter);
        // 展示分析的结果
        //showPaths(Paths);
    }
    public InputParameter initInput(){
        String source = new String("getEnv");
        int sourceIdx = -1;
//        String sink = new String("strcpy");
        String sink = new String("__strcpy_chk");
        int sinkIdx = 1;
        return new InputParameter(source, sourceIdx, sink, sinkIdx);
    }
    public void dataFlowAnalysis(InputParameter inputParameter) {
        // 返回source函数被引用的所有地址
        ArrayList<Address> calledAddress = getCalledAddress(inputParameter.getSource());
// log
        // 获取包含对应地址的函数

        Function func = getFunctionContaining(calledAddress.get(0));
        
        // 生成对应函数的CFG
        CFG functionCFG = getCFGbyFunction(func);
        // dataflow
        ArrayList<Path> paths = new ArrayList<Path>();
        dataflow(functionCFG, calledAddress.get(0), inputParameter, paths);
        paths.get(0).showFunctionPath();
    }

    public void dataflow(CFG cfg, Address sourceAddress, InputParameter inputParameter, ArrayList<Path> paths) {
        ArrayList<BasicBlock> basicBlocks = cfg.getBasicBlocks();
        paths = new ArrayList<Path>();
        Set<Varnode> worklist = new HashSet<Varnode>();
        // init source cfg
        Set<Edge> accessedEdge = new HashSet<Edge>();
        cfg.setAccessedSet(accessedEdge);
        cfg.setIsFindSourceVarnode(false);
        BasicBlock firstBlock = basicBlocks.get(0);
        Path path = new Path();
        path.addVarnodeAddress(sourceAddress);
        paths.add(path);
        cfgBlockFlow(cfg, firstBlock, sourceAddress, inputParameter, paths, worklist, path);
    }

    public void cfgBlockFlow(CFG cfg, BasicBlock basicBlock, Address sourceAddress, InputParameter inputParameter, ArrayList<Path> paths, Set<Varnode> worklist, Path path){
        
        accessInstructions(cfg, basicBlock, sourceAddress, inputParameter.getSourceIdx(), worklist);
        if(worklist.size() == 0){
            return;
        }
        accessPcodeOps(cfg, basicBlock, worklist, inputParameter.getSinkIdx(), paths, inputParameter, sourceAddress, path);
        Set<BasicBlock> successors = basicBlock.getSuccessor();
        for(BasicBlock successorBasicBlock : successors) {
            Edge edge = new Edge(basicBlock.getIdx(), successorBasicBlock.getIdx());
            if(!isAccessedEdge(cfg, edge)) {
                edge.show();
                if(cfg.getIsFindSourceVarnode()){
                    cfg.addAccessEdge(edge);
                }
                cfgBlockFlow(cfg, successorBasicBlock, sourceAddress, inputParameter, paths, worklist , path);
            }
        }
    }

    private class Path{
        ArrayList<String> functionPath;
        ArrayList<Address> varnodePropagatePath;
        Path(){
            this.functionPath = new ArrayList<String>();
            this.varnodePropagatePath = new ArrayList<Address>();
        }
        public void showFunctionPath(){
            printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~ path show ~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            printf("<function path>");
            for( String funcName : functionPath){
                printf("[%s] -> ", funcName);
            }
            printf("<address path>");
            for( Address address : varnodePropagatePath){
                printf("[0x%s] - ", address.toString());
            }
        }
        public void addVarnodeAddress(Address address){
            this.varnodePropagatePath.add(address);
        }
        public void addFunctionStr(String functionName){
            this.functionPath.add(functionName);
        }
    }

    public void accessPcodeOps(CFG cfg, BasicBlock basicBlock , Set<Varnode> worklist, int sinkIdx, ArrayList<Path> paths , InputParameter inputParameter, Address sourceAddress , Path path){

        if(cfg.getIsFindSourceVarnode()){
            printf("[pcodeOp flow] block %d", basicBlock.getIdx());
            int pcodeOpIdx = cfg.getPcodeIdx();
            ArrayList<PcodeOp> pcodes = basicBlock.getPcodeOps();
            int maxIdx = pcodes.size() - 1;
            for(; pcodeOpIdx <= maxIdx; pcodeOpIdx ++ ){
                ArrayList<Varnode> resVarnode = new ArrayList<Varnode>();
                ArrayList<String> functionName = new ArrayList<String>();
                ArrayList<Address> addressVarnode = new ArrayList<Address>();
                // for (Varnode vn : worklist){
                //     printf("[+++++++ into] worklist varnode = %s", vn);
                // }
                PcodeOp op = pcodes.get(pcodeOpIdx);
                printf("[pcodeOp] + %d --- %s" , pcodeOpIdx, pcodes.get(pcodeOpIdx).toString());
                if(isFindPathSourceToSink(op, inputParameter, worklist, functionName, addressVarnode)){
                    // path add sink varnode address , and sink function
                    println("---------------------------------------- find the path ----------------------------------------");
                    path.addVarnodeAddress(addressVarnode.get(0));
                    path.addFunctionStr(functionName.get(0));
                    paths.add(path);
                        // todo 
                        // find address by pcodeOpIdx
                    // AddressSpace registerSpace = currentProgram.getAddressFactory().getRegisterSpace();
                    // Address address = registerSpace.getAddress(0x0);
                    // // get return register
                    // Varnode returnRegister = new Varnode(address, 8);
                    // Varnode returnRegister2 = new Varnode(address, 4);
                    // if(worklist.contains(returnRegister)){
                    //     worklist.remove(returnRegister);
                    // }else if(worklist.contains(returnRegister2)){
                    //     worklist.remove(returnRegister2);
                    // }
                }
                // if varnode in worklist be covered , need to remove the varnode from worklist
                // 1. execve CALL opcode
                // 2. execve COPY opcode , the output varnode in worklist
                // 3. stack varnode be store , the varnode in worklist , store varnode not in worklist
                if(isFindWorklistVarnodeCovered(op, worklist, resVarnode)){
                    Varnode outVarnode = resVarnode.get(0);
                    worklist.remove(outVarnode);
                    // show worklist
                    for (Varnode vn : worklist){
                        printf("[--------]remove varnode [+] %s", vn);
                    }
                }
                // produce new varnode to worklist
                // 1. copy opcode to new varnode
                // 2. varnode in worklist store to the stack
                if(isFindNewVarnodePropagate(op, worklist, resVarnode)){
                    Varnode outVarnode = resVarnode.get(0);
                    worklist.add(outVarnode); 
                }
                // meet CALL op and not sink function , function varnode propagate 
                // if (op.CALL == op.getOpcode() && !isFindPathSourceToSink(op, inputParameter, worklist)){
                if(isTestFunctionPropagate(op)){
                    functionPropagate(sourceAddress, op, inputParameter, paths, worklist, path);
                } 
            }
        }
        cfg.setPcodeIdx(0);
    }

    public Boolean isTestFunctionPropagate(PcodeOp op ){
        boolean res = false;
        if( op.CALL == op.getOpcode()){
            String addressString = getVarnodeAddressString(op, 0);
            String funcName = getFunctionByOffset(addressString).getName();
            String tmp = new String("tmp");
            if(tmp.equals(funcName)){
                res = true;
            }
        }
        return res;
    }

    public void functionPropagate(Address sourceAddress, PcodeOp pcodeOp, InputParameter inputParameter, ArrayList<Path>paths, Set<Varnode> worklist, Path path){
        String addressString = getVarnodeAddressString(pcodeOp, 0);
        Function func = getFunctionByOffset(addressString);
        
        CFG cfg = getCFGbyFunction(func);
        BasicBlock firstBlock = cfg.getBasicBlocks().get(0);
        cfg.setIsFindSourceVarnode(true);
        cfg.setPcodeIdx(0);
        cfgBlockFlow(cfg, firstBlock, sourceAddress, inputParameter, paths, worklist, path);
    }

    public Boolean isFindWorklistVarnodeCovered(PcodeOp pcodeOp, Set<Varnode> worklist, ArrayList<Varnode> resVarnode){
        boolean res = false;
        // worklist varnode be covered by copy
        if( pcodeOp.COPY == pcodeOp.getOpcode()){

            for ( Varnode vn : worklist){
                if(isEqualVarnode(vn, pcodeOp.getOutput(), false)){
                    resVarnode.add(vn);
                    res = true;
                    break;
                }
            }
        }
        // call function mov return function from worklist
        else if( pcodeOp.CALL == pcodeOp.getOpcode()){
            printf("---------------------------------------------------------------------- into call pcodeop %s", pcodeOp.toString());
            AddressSpace registerSpace = currentProgram.getAddressFactory().getRegisterSpace();
            Address address = registerSpace.getAddress(0x0);
            Varnode returnRegister = new Varnode(address, 8);
            for ( Varnode vn : worklist){
                printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ try find equal varnode %s =? %s", vn.toString(), returnRegister.toString());
                printf("is ??????????????????  %B", isEqualVarnode(vn, returnRegister, false));
                if(isEqualVarnode(vn, returnRegister, false)){
                    resVarnode.add(vn);
                    res = true;
                    break;
                }
            }
        }
        // stack varnode be covered by stack store
        return res;
    }

    public Boolean isFindNewVarnodePropagate(PcodeOp pcodeOp, Set<Varnode> worklist, ArrayList<Varnode> resVarnode){
        boolean res = false;
        // copy
        if( pcodeOp.COPY == pcodeOp.getOpcode() && worklist.contains(pcodeOp.getInput(0)) ){
            res = true;
            resVarnode.add(pcodeOp.getOutput());
        }
        // stack store
        else if ( true){
            // todo 
        }
        return res;
    }

                // find the path from source to sink
                //1. execve call opcode
                //2. call function name equals sink function name
                //3. worklist contain sink function index
    public Boolean isFindPathSourceToSink(PcodeOp pcodeOp, InputParameter inputParameter, Set<Varnode> worklist, ArrayList<String> functionName, ArrayList<Address> addressVarnode) {
        String sinkFucntionName = inputParameter.getSink();
        boolean res = false;
        //1 
        if ( pcodeOp.CALL == pcodeOp.getOpcode()){
            String addressString = getVarnodeAddressString(pcodeOp, 0);
            addressVarnode.add(currentProgram.getAddressFactory().getAddress(addressString));
            String funcName = getFunctionByOffset(addressString).getName();
            //2 
            if (sinkFucntionName.equals(funcName)){
                functionName.add(funcName);
                Varnode sinkVarnode = pcodeOp.getInput(inputParameter.getSinkIdx()+1);
                //3 
                // log : into the sink function
                printf("<log> : into the sink function");
                for ( Varnode varnode : worklist){
                    printf("<worklist id>, %s", varnode.toString());
                }
                if(worklist.contains(sinkVarnode)){
                    res = true; 
                }
            }
        }
        return res;
    }

    public Function getFunctionByOffset(String addressString){

        println("<String Address>" + addressString);
        Address targetAddress = currentProgram.getAddressFactory().getAddress(addressString);
        return  getFunctionAt(targetAddress); 

    }
    // 在没有找到source address 对应的varnode之前，访问基本块的指令
    public void accessInstructions(CFG cfg, BasicBlock basicBlock, Address sourceAddress, int sourceIdx, Set<Varnode> worklist ) {
        
        if(!cfg.getIsFindSourceVarnode()){
            printf("[instruction flow] block %d", basicBlock.getIdx());
            int pcodeOpIdx = 0;
            int instructionIdx = 0;
            ArrayList<Instruction> instructions = basicBlock.getInstrucitons();
            for ( Instruction ist : instructions ){
                Address istAddress = ist.getFallThrough();
                if (istAddress != null && istAddress.toString().equals(sourceAddress.toString())){
                    instructionIdx ++;
                    Instruction targetInstruction = instructions.get(instructionIdx);
                    cfg.setIsFindSourceVarnode(true);
                    for ( PcodeOp op : targetInstruction.getPcode() ){
                        if(op.CALL == op.getOpcode()){
                            
                            cfg.setPcodeIdx(pcodeOpIdx + 1);
                            break;
                        }
                        pcodeOpIdx ++;
                    }
                    break;
                }
                println("instruction = " + ist);
                println("[address] instruction = " + ist.getFallThrough());
                for ( PcodeOp op : ist.getPcode() ){
                    pcodeOpIdx ++;
                }
                instructionIdx ++;
            }
            if(cfg.getIsFindSourceVarnode()){
                ArrayList<PcodeOp> pcodes = basicBlock.getPcodeOps();
                int pcodeIdx = cfg.getPcodeIdx();
                PcodeOp callPcodeOp = pcodes.get(pcodeIdx);
                cfg.setPcodeIdx(pcodeIdx+1);
                if(sourceIdx == -1 ){
                    worklist.add(callPcodeOp.getOutput());
                }else if (sourceIdx > 0){
                    worklist.add(callPcodeOp.getInput(sourceIdx));
                }
            }
        }
    }

    public Boolean isAccessedEdge(CFG cfg, Edge edge){
        return cfg.getAccessedEdge().contains(edge);
    }

    private class Edge{
        int from;
        int to;
        Edge(int from, int to){
            this.from = from;
            this.to = to;
        }
        public void show(){
            printf("[edge] %d --> %d", this.from, this.to);
        }
    }

    public CFG getCFGbyFunction(Function function){
        ArrayList<BasicBlock> basicBlocks = getBasicBlockByFunction(function);
        // 生成cfg
        CFG cfg = new CFG(basicBlocks);
        // show
        cfg.showBasicBlocksPcodeOps();
        cfg.showEdge();
        return cfg;
    }

    public ArrayList<Address> getCalledAddress(String name){
        ArrayList<Address> calledAddress = new ArrayList<Address>();
        Function func = getFunctionByName(name);
        if (func == null){
            println("[!]");
            println("get Function By Name is null\n" + "can't find <" + name + "> function");
            System.exit(0);
        }
        Address addr = func.getEntryPoint();
        Reference refs[] = getReferencesTo(addr);
        for (int i = 0; i < refs.length; i++) { 
            if (refs[i].getReferenceType().isCall()) {
                calledAddress.add(refs[i].getFromAddress());
                // 取包含这个地址的函数
                // Function func = getFunctionContaining(src);
            }
        }
        return calledAddress;
    }

    public Function getFunctionByName(String name) {
        SymbolTable symtab = currentProgram.getSymbolTable();
        SymbolIterator si = symtab.getSymbolIterator();
        Function targetFunction = null;
        while (si.hasNext()) {
            Symbol s = si.next();
            if (s.getSymbolType() != SymbolType.FUNCTION || s.isExternal()) {
                continue;
            }
            if (s.getName().equals(name)) {
                targetFunction = getFunctionAt(s.getAddress());
                break;
            }
        }
        return targetFunction;
    }

    private class InputParameter{
        private String source;
        private int sourceIdx;
        private String sink;
        private int sinkIdx;
        InputParameter(String source, int sourceIdx, String sink, int sinkIdx){
            this.source = source;
            this.sourceIdx = sourceIdx;
            this.sink = sink;
            this.sinkIdx = sinkIdx;
        }
        public String getSource(){
            return this.source;
        }
        public int getSourceIdx(){
            return this.sourceIdx;
        }
        public String getSink(){
            return this.sink;
        }
        public int getSinkIdx(){
            return this.sinkIdx;
        }
    }

    private class CFG {
        private int pcodeOpIdx;
        private boolean isFindSourceVarnode;
        private Address entryPoint;
        private Set<Edge> accessedSet;
        private ArrayList<BasicBlock> basicBlocks;

        CFG(ArrayList<BasicBlock> basicBlocks){
            printf("====================================================================================================");
            printf("||                                          new cfg                                               ||");
            printf("====================================================================================================");
            this.entryPoint = basicBlocks.get(0).getStart();
            this.basicBlocks = basicBlocks;
            Listing plist = currentProgram.getListing();
            int basicBlockIndex = 0;
            for (BasicBlock basicBlock : basicBlocks) {
                // gen raw pcodes and instructions
                InstructionIterator iter = plist.getInstructions(basicBlock.getStart(), true);
                ArrayList<PcodeOp> pcodes = new ArrayList<PcodeOp>();
                ArrayList<Instruction> instructions = new ArrayList<Instruction>();
                long endOffset = basicBlock.getEnd().getOffset();
    // -- log
                println("[block]");
                // 
                ArrayList<Integer> pcodeOpCallindexs = new ArrayList<Integer>();
                int indexPcodeOp = 0; 
                while (iter.hasNext() && !monitor.isCancelled()) {
                    Instruction ist = iter.next();
    // -- log
                    println("[instruction] - " + ist);
                    Address istAddress = ist.getPrevious().getFallThrough();
                    if(istAddress == null){
                        instructions.add(ist);
                        // add pcode
                        for (PcodeOp op : ist.getPcode()) {
                            pcodes.add(op);
                            if(op.CALL == op.getOpcode() || op.CALLIND == op.getOpcode()){
                                pcodeOpCallindexs.add(indexPcodeOp);
                            }
                            indexPcodeOp ++ ;
                        }
                    }else{
                        if( istAddress.getOffset() > endOffset){
                            break;
                        }else{
                            instructions.add(ist);
                            for (PcodeOp op : ist.getPcode()) {
    // -- log
                                println("[PcodeOp] - " + op);
                                pcodes.add(op);
                                if(op.CALL == op.getOpcode() || op.CALLIND == op.getOpcode()){
                                    pcodeOpCallindexs.add(indexPcodeOp);
                                }
                                indexPcodeOp ++ ;
                            }
                            if(istAddress.getOffset() == endOffset){
                                break;
                            }
                        }
                    }
                }
                basicBlock.setInstructions(instructions);
                // refine call pcodeop
                refineCall(pcodes, pcodeOpCallindexs);
                basicBlock.setPcodeOps(pcodes);
                // add edge
                setEdge(basicBlock, basicBlockIndex);
                basicBlockIndex ++;
            }
        }
        public void addAccessEdge(Edge accessEdge){
            this.accessedSet.add(accessEdge);
        }
        public void setPcodeIdx(int pcodeOpIdx){
            this.pcodeOpIdx = pcodeOpIdx;
        }
        public void setIsFindSourceVarnode(boolean isFindSourceVarnode){
            this.isFindSourceVarnode = isFindSourceVarnode;
        }
        public void setAccessedSet(Set<Edge> accessedSet) {
            this.accessedSet = accessedSet;
        }
        public int getPcodeIdx(){
            return this.pcodeOpIdx;
        }
        public Boolean getIsFindSourceVarnode(){
            return this.isFindSourceVarnode;
        }
        public Set<Edge> getAccessedEdge() {
            return this.accessedSet;
        }

        public ArrayList<BasicBlock> getBasicBlocks(){
            return this.basicBlocks;
        }

        public Address getEntryPoint(){
            return this.entryPoint;
        }

        private void setEdge(BasicBlock basicBlock, int basicBlockIndex){
            Set<BasicBlock> successors = new HashSet<BasicBlock>();
            ArrayList<Instruction> instructions = basicBlock.getInstrucitons();
            Instruction lastInstruction  = instructions.get(instructions.size() - 1);
            // 直接后继 后续不是goto return
            addImmediateSuccessor(successors, lastInstruction, basicBlockIndex);
            // goto 后继
            addGotoSuccessor(successors, lastInstruction);
            basicBlock.setSuccessor(successors);
        }

        private void addGotoSuccessor(Set<BasicBlock> successors, Instruction lastInstruction){
            long addressOffset = 0;
            ArrayList<BasicBlock> basicBlockPointer = new ArrayList<BasicBlock>();
            for (PcodeOp op : lastInstruction.getPcode()) {
                if(isJumpInstruction(op)){
                    //Address gotoAddress = getGotoAddressByPcodeOp(op));
                    addressOffset = getVarnodeAddress(op, 0);
                }        
                if(findBasicBlockByOffset(basicBlockPointer, addressOffset)){
                    successors.add(basicBlockPointer.get(0));
                }
            }
        }   

        private Boolean findBasicBlockByOffset(ArrayList<BasicBlock> basicBlockPointer, long addressOffset){
            boolean res = false;
            for ( BasicBlock basicBlock : this.basicBlocks ){
                if(addressOffset >= basicBlock.getStart().getOffset() && addressOffset <= basicBlock.getEnd().getOffset()){
                    basicBlockPointer.add(basicBlock);
                    res = true;
                    break;
                }
            }
            return res;
        }

        private Boolean addImmediateSuccessor(Set<BasicBlock> successors, Instruction lastInstruction, int basicBlockIndex){
            
            for (PcodeOp op : lastInstruction.getPcode()) {
                if(isGotoJump(op) || isReturn(op))
                    return false;
            }
            if (basicBlockIndex + 1 < this.basicBlocks.size())
                successors.add(this.basicBlocks.get(basicBlockIndex + 1));
            return true;
        }

        private void refineCall(ArrayList<PcodeOp> pcodes, ArrayList<Integer> callIndexs) {
            // arg0 rdi (register, 0x38, 8)
            // arg1 ESI (register, 0x30, 8)
            // arg2 EDX (register, 0x10, 8)
            // arg3 ECX (register, 0x8, 8)
            // arg4 R8D (register, 0x80, 8)
            // arg5 R9D (register, 0x88, 8)
            // set call output varnode
            AddressSpace registerSpace = currentProgram.getAddressFactory().getRegisterSpace();
            Address address = registerSpace.getAddress(0x0);
            // get return register
            Varnode returnRegister = new Varnode(address, 8);
            ArrayList<Varnode> argRegisters = getArgRegisters(registerSpace);
            for (int idx : callIndexs) {
                PcodeOp op = pcodes.get(idx);
                if(isUseReturnRegister(pcodes, idx+1, returnRegister)){
                    op.setOutput(returnRegister);
                }
                ArrayList<Varnode> varnodeArgs = getVarnodeArgs(pcodes, argRegisters, idx - 1);
                int argIndex = 1; 
                for(Varnode varnode : varnodeArgs){
                    op.setInput(varnode, argIndex);
                    argIndex ++;
                }
                pcodes.set(idx, op);
            }
        }

        private ArrayList<Varnode> getVarnodeArgs(ArrayList<PcodeOp> pcodes, ArrayList<Varnode> argVarnodes, int idxStart){
// log
            printf("!!!!!!!!!!!!!!!!!!!!!!!!!%d", idxStart);
            // 不考虑通过栈传参的情况
            ArrayList<Varnode> varnodeArgs = new ArrayList<Varnode>();
            //addPushVarnodes(pcodes, newArgVarnodes, idx - 2);
            // analysis register arg
            for (Varnode varnode : argVarnodes){
                boolean isChange = false;
                for ( int idx = idxStart; idx >= 0 ; idx-- ){
                    ArrayList<Varnode> loadVarnode = new ArrayList<Varnode>();
                    // printf("[-] %d\n", idx);
                    // printf("[varnode] %s\n", varnode.toString());
                    PcodeOp pcodeOp = pcodes.get(idx);
                    int opcode = pcodeOp.getOpcode();
                    if( opcode == pcodeOp.COPY || opcode == pcodeOp.INT_ZEXT || opcode == pcodeOp.INT_SEXT ){
                        if(isEqualVarnode(varnode, pcodeOp.getOutput(), false)){
                            varnode = pcodeOp.getInput(0);
                            isChange = true;
                            // 如果赋值的varnode为常数类型，直接返回
                            String targetType = "const";
                            if(isTypeVarnode(varnode, targetType)){
                                break;
                            }
                        }
                    }else if(canLoadVarnode(pcodes, loadVarnode, varnode, idx)){
                        varnode = loadVarnode.get(0);
                        isChange = true;
                        // 如果赋值的varnode为常数类型，直接返回
                        String targetType = "const";
                        if(isTypeVarnode(varnode, targetType)){
                            break;
                        }
                    }else if( opcode == pcodeOp.CALL || opcode == pcodeOp.CALLIND){
                        break;
                    }
                } 
                if(isChange){
                    varnodeArgs.add(varnode);
                }else{
                    break;
                }
            }
            // analysis push arg
            return varnodeArgs;
        }
        // (unique, 0x3100, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffee, 8)
        private Boolean canLoadVarnode(ArrayList<PcodeOp> pcodes, ArrayList<Varnode> loadVarnode, Varnode varnode, int idx){
            // baseReg
            AddressSpace registerSpace = currentProgram.getAddressFactory().getRegisterSpace();
            Address address = registerSpace.getAddress(0x28);
            Varnode baseReg = new Varnode(address, 8);

            boolean res = false;
            PcodeOp pcode = pcodes.get(idx);
            // mov r1, rbp[offset];
            if ( pcode.LOAD == pcode.getOpcode() && isEqualVarnode(varnode, pcode.getOutput(), false) ){
                if(idx > 0){
                    Varnode varnodefrom = pcode.getInput(1);
                    PcodeOp prePcodeOp = pcodes.get(idx - 1);
                    if( prePcodeOp.INT_ADD == prePcodeOp.getOpcode() && isEqualVarnode(varnodefrom, prePcodeOp.getOutput(), false) && isEqualVarnode(baseReg, prePcodeOp.getInput(0), false)){
                        loadVarnode.add(prePcodeOp.getInput(1));
                        res = true;
                    }
                }
            } //  LEA RAX,[RBP + -0x12]
            else if ( pcode.INT_ADD == pcode.getOpcode() && isEqualVarnode(baseReg, pcode.getInput(0), false) && isEqualVarnode(varnode, pcode.getOutput(), false)){
                loadVarnode.add(pcode.getInput(1));
                res = true;
            }
            return res;
        }
        // jump push address to stack
        private void addPushVarnodes(ArrayList<PcodeOp> pcodes, ArrayList<Varnode> argVarnodes, int idx){
            AddressSpace registerSpace = currentProgram.getAddressFactory().getRegisterSpace();
            Address address = registerSpace.getAddress(0x20);
            Varnode stackRegVarcode = new Varnode(address, 8);
            for ( ; idx > 0 ; idx -- ){
                PcodeOp pcodeOp = pcodes.get(idx);
                if ( pcodeOp.STORE == pcodeOp.getOpcode() ){
                    Varnode input1 = pcodeOp.getInput(1);
                    Varnode input2 = pcodeOp.getInput(2);
                    PcodeOp prePcodeOp = pcodes.get(idx -1);
                    if(isEqualVarnode(stackRegVarcode, input1, false) && isPushOp(prePcodeOp, stackRegVarcode)){
                        argVarnodes.add(input2);
                    }
                }else if( pcodeOp.CALL == pcodeOp.getOpcode() || pcodeOp.CALLIND == pcodeOp.getOpcode()){
                    break;
                }
            }
        }

        private boolean isPushOp(PcodeOp prePcodeOp, Varnode stackRegVarcode){
            return (prePcodeOp.INT_SUB == prePcodeOp.getOpcode()) && isEqualVarnode(stackRegVarcode, prePcodeOp.getOutput(), false) && isEqualVarnode(stackRegVarcode, prePcodeOp.getInput(0), false);
        }

        private ArrayList<Varnode> getArgRegisters(AddressSpace regSpace){
            ArrayList<Varnode> argRegs = new ArrayList<Varnode>();
            argRegs.add(new Varnode(regSpace.getAddress(0x38), 8));
            argRegs.add(new Varnode(regSpace.getAddress(0x30), 8));
            argRegs.add(new Varnode(regSpace.getAddress(0x10), 8));
            argRegs.add(new Varnode(regSpace.getAddress(0x8), 8));
            argRegs.add(new Varnode(regSpace.getAddress(0x80), 8));
            argRegs.add(new Varnode(regSpace.getAddress(0x88), 8));
            return argRegs;
        }

        private boolean isUseReturnRegister(ArrayList<PcodeOp> pcodes, int index, Varnode returnRegister){
            int maxIndex = pcodes.size() - 1;
            boolean res = false;
            
            for (; index <= maxIndex; index ++ ) {
                PcodeOp pcodeop = pcodes.get(index);
                int opcode = pcodeop.getOpcode();
                if(opcode == pcodeop.COPY || opcode == pcodeop.INT_ZEXT || opcode == pcodeop.INT_SEXT ){
                    
                    // reg is copyed return true
                    if (isEqualVarnode(pcodeop.getInput(0), returnRegister, false)){
                        res = true;
                        break;
                    }else if (isEqualVarnode(pcodeop.getOutput(), returnRegister, false)) {
                        break;
                    }
                }else if(opcode == pcodeop.CALL || opcode == pcodeop.CALLIND){
                    break;
                }
            }
            return res;
        } 

        // show instructions
        public void showBasicBlocksInstructions() {
            int nums = this.basicBlocks.size();
            for (int i = 0 ; i < nums ; i++){
                printf("---------- block %d ----------\n", i);
                
                for (Instruction ist : this.basicBlocks.get(i).getInstrucitons()){
                    println("[+ instruction] : " + ist);
                }
                println("->");
            }
        }

        // show pcodeops
        public void showBasicBlocksPcodeOps() {
            int nums = this.basicBlocks.size();
            for (int i = 0 ; i < nums ; i++){
                printf("---------- block %d ----------\n", i);
                int j = 0;
                for (PcodeOp pcodeop : this.basicBlocks.get(i).getPcodeOps()){
                    printf("[+ PcodeOp -%d] %s: ", j, pcodeop.toString());
                    j++;
                }
                println("->");
            }
        }

        public void showEdge() {
            int nums = this.basicBlocks.size();
            for (int i = 0 ; i < nums ; i++){
                printf("++++++++++++++++++++++++++++++++++++++++++++++++\n");
                printf("address: %s\n", this.basicBlocks.get(i).getStart().toString());
                printf("+----------+\n");
                printf("| block %-3d| --->\n", i);
                printf("+----------+\n");
                for (BasicBlock basicBlock : this.basicBlocks.get(i).getSuccessor()){
                    printf("             address: %s\n", basicBlock.getStart().toString());
                    printf("             +----------+\n");
                    printf("[precursor]->| block %-3d|\n" , basicBlock.getIdx());
                    printf("             +----------+\n");
                }
            }
        }
    }


    private class BasicBlock {
        private int idx;
        private Address start;
        private Address end;
        private ArrayList<Instruction> instructions;
        private ArrayList<PcodeOp> pcodeOps;
//        private ArrayList<int> pcodeOpCallindexs;
        private Set<BasicBlock> successors;

        

        BasicBlock(Address start, Address end, int idx){
            this.start = start;
            this.end = end;
            this.idx = idx;
        }
        public void setIdx(int idx){
            this.idx = idx;
        }
        public void setPcodeOps(ArrayList<PcodeOp> pcodeOps){
            this.pcodeOps = pcodeOps;
        }
        public void setTargetPcodeOp(int index, PcodeOp pcodeOp){
            this.pcodeOps.set(index, pcodeOp);
        }
        public void setSuccessor(Set<BasicBlock> successors){
            this.successors = successors;
        }
        public void setInstructions(ArrayList<Instruction> instructions){
            this.instructions = instructions;
        }
        // public void setPcodeOpCallindexs(ArrayList<int> indexs){
        //     this.pcodeOpCallindexs = index;
        // }
        public int getIdx(){
            return this.idx;
        }
        public Address getStart(){
            return this.start;
        }
        public Address getEnd(){
            return this.end;
        }
        public ArrayList<PcodeOp> getPcodeOps() {
            return this.pcodeOps;
        }
        public Set<BasicBlock> getSuccessor() {
            return this.successors;
        }
        public ArrayList<Instruction> getInstrucitons(){
            return this.instructions;
        }
        // public ArrayList<int> getPcodeOpCallindexs() {
        //     return this.pcodeOpCallindexs;
        // }
    }

    public ArrayList<BasicBlock> getBasicBlockByFunction(Function func){
            // add address by three func
            ArrayList<Address> leaders= new  ArrayList<Address>();
            Listing plist = currentProgram.getListing();
            InstructionIterator iter = plist.getInstructions(func.getBody(), true);
            // one
            Instruction ist = iter.next();
            while(ist.getFallFrom() == null){
                ist = iter.next();
            }
            leaders.add(ist.getFallFrom());
            boolean needNext = false;
            while (iter.hasNext() && !monitor.isCancelled()) {
                if(needNext){
                    ist = iter.next();
                }else{
                    needNext = true;
                }
                for (PcodeOp op : ist.getPcode()) {
                    // two
                    if(isJumpInstruction(op)){
                        Address theAddr = op.getInput(0).getAddress();
                        if(!leaders.contains(theAddr) && theAddr !=null){
                            leaders.add(theAddr);
                        }
                    }
                    // three
                    if(isIfJump(op)){
                        Address nextAddr = ist.getFallThrough();
                        long nextOffset = nextAddr.getOffset();
                        if(nextAddr != null && !leaders.contains(nextAddr))
                            leaders.add(nextAddr);
                    }
                }
            }
            leaders.sort(Comparator.naturalOrder());
            Address endAddress = ist.getPrevious().getFallThrough();

            ArrayList<BasicBlock> basicBlocks = getBasicBlocksByLeaders(leaders, endAddress);
            return basicBlocks;
        } 

    public ArrayList<BasicBlock> getBasicBlocksByLeaders(ArrayList<Address> leaders, Address endAddress){
        
            int size = leaders.size();
            ArrayList<BasicBlock> basicBlocks = new ArrayList<BasicBlock>();
            Address start;
            Address next;
            int p = 0 , q = 1 ;
            for (; q < size ; p++ , q++){ 
                start = leaders.get(p);
                next = leaders.get(q);
                Instruction nextIns = currentProgram.getListing().getInstructionAt(next);
                Instruction endIst = nextIns.getPrevious().getPrevious();
                Address end = endIst.getFallThrough();
                printf("<start> address : %s", start.toString());
                printf("<end> address : %s", end.toString());
                basicBlocks.add(new BasicBlock(start, end, p));
            }
            start = leaders.get(p);
            printf("<start> address : %s", start.toString());
            printf("<end> address : %s", endAddress.toString());
            basicBlocks.add(new BasicBlock(start, endAddress, p));

            return basicBlocks;
        }

    // 比较两个Varnode是否相同，addOffset是true，则将偏移加入比较，否则不加
    public boolean isEqualVarnode(Varnode v1, Varnode v2, boolean addOffset) {
        String v1Slice[] = v1.toString().split(",");
        String v2Slice[] = v2.toString().split(",");
        boolean res = true;
        int nums = 2;
        if(addOffset) {
            nums = 3;
        }
        for (int i = 0 ; i < nums ; i++){
            if(!v1Slice[i].equals(v2Slice[i])){
                res = false;
                break;
            }
        }
        return res;
    }
    // get bb by func
    
    public Boolean isReturn(PcodeOp op) {

        int opcode = op.getOpcode();
        if( opcode == op.RETURN ) {
            return true;
        }else{
            return false;
        }
    }

    public Boolean isGotoJump(PcodeOp op) {

        int opcode = op.getOpcode();
        if( opcode == op.BRANCH || opcode == op.BRANCHIND ) {
            return true;
        }else{
            return false;
        }
    }

    public Boolean isIfJump(PcodeOp op){
        
        int opcode = op.getOpcode();
        if( opcode == op.CBRANCH ){
            return true;
        }else{
            return false;
        }
    }

    public Boolean isJumpInstruction(PcodeOp op){

        int opcode = op.getOpcode();
        if( opcode == op.BRANCH || opcode == op.CBRANCH || opcode == op.BRANCHIND ){
            return true;
        }else{
            return false;
        }
    }

    // find function by function name
    public Function findFunction(String target){
        Function func = getFirstFunction();
        String name = func.getName();
        while (!name.equals(target) && func != null && !monitor.isCancelled()) {
            func = getFunctionAfter(func);
            name = func.getName();
        }
        return func;
    }
    // 获取varnode中的地址偏移
    // (register, 0x28, 8) 获取 0x28
    // (ram, 0x101242, 8) 获取 0x101242
    private long getVarnodeAddress(PcodeOp pcodeOp, int idx){
        Varnode varnode;
        if(idx >= 0){
            varnode = pcodeOp.getInput(idx);
        }
        else{
            varnode = pcodeOp.getOutput();
        }
        String v1Slice[] = varnode.toString().split(",");
        String addressStr = v1Slice[1].substring(3, v1Slice[1].length());

        return Long.parseLong(addressStr, 16);
    }
    private String getVarnodeAddressString(PcodeOp pcodeOp, int idx){
        Varnode varnode;
        if(idx >= 0){
            varnode = pcodeOp.getInput(idx);
        }
        else{
            varnode = pcodeOp.getOutput();
        }
        String v1Slice[] = varnode.toString().split(",");
        String addressStr = v1Slice[1].substring(3, v1Slice[1].length());
         
        return addressStr;
    }
    public Boolean isTypeVarnode(Varnode varnode, String targetType){
        String splitVarnode[] = varnode.toString().split(",");
        String typeVarnode = splitVarnode[0].substring(1, splitVarnode[0].length());
        return targetType.equals(typeVarnode);
    }
    
}