class Constant:
	def __init__(self):
		self.level = "none"
	
	def eval(self):
		return self.level

class Variable:
	def __init__(self, level):
		self.level = level

	def eval(self):
		return self.level

class Expression:
	def __init__(self, left, right):
		self.left = left
		self.right = right

	def eval(self):
		self.left.eval()
		self.right.eval()


class CompoudStatements:
	def __init__(self, first, second):
		self.firstStattement = first
		self.secondStatement = second

	def eval(self):
		self.firstStattement.eval()
		self.secondStatement.eval()

class Statement:
	pass

class Assignment(Statement):
	def __init__(self, variable, expression):
		self.variable = variable
		self.expression = expression

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