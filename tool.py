import sys, json, utils

def createAst(input):
    ast = json.loads(input)
    body = ast['body']
    for i in body:
        print(i)

if __name__ == "__main__":
    f = open(sys.argv[1], "r")
    createAst(f.read())
