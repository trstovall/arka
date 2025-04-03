
import arka.messages as messages

def test_auto():
    #
    print("messages.SocketMessageEnum")
    for i in dir(messages.SocketMessageEnum):
        if not i.startswith('__'):
            print((i, getattr(messages.SocketMessageEnum, i).value))
    print()


if __name__ == "__main__":
    #
    print("test_auto()")
    test_auto()

