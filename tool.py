import sys, json, createObject, copy, utils
from variablesBuffer import VariablesBuffer
from vulnerabilitiesReport import VulnerabilitiesReport
#import ast

def parsePatterns(patternsJson):
    result = []
    for pattern in patternsJson:
        result.append(pattern)
    return result

def setupVariablesTaintness(variableBuffer, patterns):
    for sink in patterns["sinks"]:
        if sink in variableBuffer.keys():
            variableBuffer[sink].type = "sink"
            variableBuffer[sink].tainted = False
    
    for source in patterns["sources"]:
        if source in variableBuffer.keys():
            variableBuffer[source].type = "source"
            variableBuffer[source].tainted = True
        

def createAst(astTreeInput, patternsInput):
    patterns = parsePatterns(json.loads(patternsInput))
    VulnerabilitiesReport.setup(patterns)
    astInput = json.loads(astTreeInput)
    astBody = astInput["body"]
    body = createObject.createBodyObject(astBody)
    print(body)
    print("-----EVALUATE----")
    initialVariableBuffer = VariablesBuffer.getBufferDeepCopy()
    for pattern in patterns:
        variableBuffer = copy.deepcopy(initialVariableBuffer)
        setupVariablesTaintness(variableBuffer, pattern)
        #print(pattern)
        taintTheTree(pattern, variableBuffer, body)
    
    print(VulnerabilitiesReport.errors)

def taintTheTree(pattern,variableBuffer, body):
    for statement in body.statementsList:
        if isinstance(statement, utils.If) or isinstance(statement, utils.While):
            print("TODO")
        else:
            statement.isTainted(pattern, variableBuffer)


if __name__ == "__main__":
    astTree = open(sys.argv[1], "r")
    patterns = open(sys.argv[2], "r")
    
    createAst(astTree.read(),patterns.read())
