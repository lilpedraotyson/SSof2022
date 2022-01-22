import sys, json, utils, createObject
#import ast


def createAst(input):
    variablesBuffer = {}
    astInput = json.loads(input)
    astBody = astInput["body"]
    body = createObject.createBodyObject(astBody)
    print(body)

if __name__ == "__main__":
    f = open(sys.argv[1], "r")
    
    createAst(f.read())
