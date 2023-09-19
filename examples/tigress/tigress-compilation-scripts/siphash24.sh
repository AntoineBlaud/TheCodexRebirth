#!/bin/bash

seed=$1
input=$2
output=$3
jitter=$4

tigress --Verbosity=1 --Environment=x86_64:Linux:Gcc:4.6 --Seed=$seed --FilePrefix=obf \
      --Transform=InitImplicitFlow \
        --InitImplicitFlowHandlerCount=10 \
        --Functions=siphash24 \
    --Transform=Virtualize \
         --Functions=siphash24 --VirtualizeDispatch=switch,direct,indirect,call,ifnest \
         --VirtualizeOperands=stack \
         --Skip=false \
    --Transform=AntiTaintAnalysis \
         --Functions=siphash24 \
         --AntiTaintAnalysisKinds=argv \
    --Transform=InitBranchFuns \
         --InitBranchFunsCount=10 \
    --Transform=AntiBranchAnalysis \
         --Functions=siphash24 \
         --AntiBranchAnalysisKinds=branchFuns \
    --Transform=InitEntropy \
        --Functions=siphash24 \
        --InitEntropyKinds=vars \
     --Transform=EncodeLiterals \
        --Functions=siphash24 \
     --Transform=EncodeArithmetic \
        --Functions=siphash24 \
      --out=$output.c $input.c