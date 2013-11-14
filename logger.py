class Logger:
   def __init__(self, verbose=True):
      if verbose:
         self.set_state(VerboseStateLogger)
      else:
         self._log_file = open(str(__name__ + ".log"), "w")
         self.set_state(SilentStateLogger)

   def set_state(self, newstate):
      self._state = newstate

   def write(self, data):
      return self._state.write(self,data)

class LoggerState:
   @staticmethod
   def write(log, data):
      raise NotImplementedError()

class VerboseStateLogger(LoggerState):
   @staticmethod
   def write(log, data):
      print data

class SilentStateLogger(LoggerState):
   @staticmethod
   def write(log, data):
      log._log_file.write(data)
