#!/bin/bash

seed=$1
input=$2
output=$3
jitter=$4

tigress --Verbosity=1 --Environment=x86_64:Linux:Gcc:4.6 --Seed=$seed --FilePrefix=obf \
      --Transform=InitImplicitFlow \
        --InitImplicitFlowHandlerCount=10 \
        --Functions=SECRET \
    --Transform=Virtualize \
         --Functions=SECRET --VirtualizeDispatch=switch,direct,indirect,call,ifnest \
         --VirtualizeOperands=stack \
         --Skip=false \
    --Transform=AntiTaintAnalysis \
         --Functions=SECRET \
         --AntiTaintAnalysisKinds=argv \
    --Transform=InitBranchFuns \
         --InitBranchFunsCount=10 \
    --Transform=AntiBranchAnalysis \
         --Functions=SECRET \
         --AntiBranchAnalysisKinds=branchFuns \
    --Transform=InitEntropy \
        --Functions=SECRET \
        --InitEntropyKinds=vars \
     --Transform=EncodeLiterals \
        --Functions=SECRET \
     --Transform=EncodeArithmetic \
        --Functions=SECRET \
      --out=$output.c $input.c