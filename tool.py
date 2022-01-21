import sys, json, utils, createObject
from variablesBuffer import VariablesBuffer
#import ast


def createAst(input):
    variablesBuffer = {}
    astInput = json.loads(input)
    #print(ast.parse(input))
    astBody = astInput["body"]
    statementsList = []
    for statement in astBody:
        if statement["ast_type"] == "Assign":
            object = createObject.createAssignmentObject(statement["targets"], statement["value"])
        
        elif statement["ast_type"] == "Expr":
            object = createObject.createExpressionObject(statement["value"])
        
        statementsList.append(object)
    
    body = utils.Body(statementsList) 
    print(body)

if __name__ == "__main__":
    f = open(sys.argv[1], "r")
    
    createAst(f.read())
