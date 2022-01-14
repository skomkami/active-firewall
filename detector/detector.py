from abc import ABC, abstractmethod


class Detector(ABC):

    def __init__(self):
        self.statsDb = {}

    @abstractmethod
    def initialise(self):
        return

    @abstractmethod
    def emit_event(self):
        raise NotImplementedError

    # metoda ta powinna dokonać aktualizacji bieżących statystyk
    @abstractmethod
    def update_stats(self, event):
        raise NotImplementedError

    # @abstractmethod
    # def update_stats(self, event):
    #     raise NotImplementedError


    def run(self):
        # do zainicjalizowania repozytoriów w nowym procesie
        self.initialise()
        while True:
            emitted_event = self.emit_event()
            self.update_stats(emitted_event)

