from utils import Variable
import copy

class VariablesBuffer:
    buffer = {}

    def addVariable(name):
        VariablesBuffer.buffer[name] =  Variable(name)
    
    def hasVariable(name):
        return name in VariablesBuffer.buffer.keys()
    
    def getVariableObject(name):
        return VariablesBuffer.buffer[name]
    
    def getBufferDeepCopy():
        return copy.deepcopy(VariablesBuffer.buffer)
    

        