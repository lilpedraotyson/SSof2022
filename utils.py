class Constant:
	def __init__(self, value):
		self.level = "none"
		self.value = value
	
	def __repr__(self) -> str:
		return 'Constant(%s)' % (self.value)
	
	def eval(self):
		return self.level

class Variable:
	def __init__(self, name):
		self.name = name 

	def __repr__(self) -> str:
		return 'Variable(%s)' % (self.name)

	def eval(self):
		return None

class Function:
	def __init__(self, name, argsList):
		self.name = name
		self.argsList = argsList 
	
	def __repr__(self) -> str:
		return 'Function(%s, %s)' % (self.name, self.argsList)

	def eval(self):
		for argument in self.argsList:
			argument.eval()

			

class Expression:
	def __init__(self, left, right):
		self.left = left
		self.right = right

	def eval(self):
		self.left.eval()
		self.right.eval()

class Body:
	#Statements is a list of objects of the class Statement
	def __init__(self, statementsList):
		self.statementsList = statementsList
	
	def __repr__(self) -> str:
		result = ""
		for statement in self.statementsList:
			result += '\n' + str(statement)
		return '--------------Body--------------%s' % (result)

	def eval(self):
		for statement in self.statementsList:
			statement.eval()

# class CompoudStatements:
# 	def __init__(self, first, second):
# 		self.firstStattement = first
# 		self.secondStatement = second

# 	def eval(self):
# 		self.firstStattement.eval()
# 		self.secondStatement.eval()

class Statement:
	pass

class Assignment(Statement):
	def __init__(self, variable, expression):
		self.variable = variable
		self.expression = expression
	
	def __repr__(self) -> str:
		return 'Assignment(%s, %s)' % (self.variable, self.expression)

	def eval(self):
		self.variable.eval()
		self.expression.eval()

class If(Statement):
	def __init__(self, condition, thenBlock, elseBlock):
		self.condition = condition
		self.thenBlock = thenBlock
		self.elseBlock = elseBlock

	def eval(self):
		self.condition.eval()
		self.thenBlock.eval()
		self.elseBlock.eval()

class While(Statement):
	def __init__(self, condition, block):
		self.condition = condition
		self.block = block

	def eval(self):
		self.condition.eval()
		self.block.eval()