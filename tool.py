import sys, json, createObject, copy, utils

from variablesBuffer import VariablesBuffer
from vulnerabilitiesReport import VulnerabilitiesReport
#import ast

def objectAlreadyHasSanitizedFlow(sanitizedFlows, target):
    for sanitizedFlow in sanitizedFlows:
        if sanitizedFlow == target:
            return True
    return False

def checkIfListHasVulnerabilityFlow(targetList, sink, source):
    count = 0
    for error in targetList:
        if error["source"] == source and error["sink"] == sink:
            return count
        count += 1
    return -1

def cleanErrorsOutput(errorsObject):
    output = []
    for vulnerability in errorsObject.keys():
        buffer = []
        for error in errorsObject[vulnerability]:
            index = checkIfListHasVulnerabilityFlow(buffer, error["sink"], error["source"])
            if index != -1:
                if len(error["sanitized flows"]) != 0:
                    if len(buffer[index]["sanitized flows"]) == 0:
                        buffer[index]["sanitized flows"] = [error["sanitized flows"]]
                    else:
                        if not objectAlreadyHasSanitizedFlow(buffer[index]["sanitized flows"],error["sanitized flows"] ):
                            buffer[index]["sanitized flows"].append(error["sanitized flows"])
                else:
                    buffer[index]["unsanitized flows"] = "yes"
            
            else:
                newError = {}
                suffix = len(buffer) + 1
                newError["vulnerability"] = vulnerability + "_" + str(suffix)
                newError["source"] = error["source"]
                newError["sink"] = error["sink"]
                if len(error["sanitized flows"]) != 0:
                    newError["unsanitized flows"] = "no"
                    newError["sanitized flows"] = [error["sanitized flows"]]
                else:
                    newError["unsanitized flows"] = "yes"
                    newError["sanitized flows"] = []
                buffer.append(newError)

        output += buffer
    return output


    
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
    
    print(cleanErrorsOutput(VulnerabilitiesReport.errors))

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
