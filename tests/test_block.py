
import arka.block as block

def test_block():
    #
    print("dir(Block)")
    for i in dir(block):
        if i.startswith('OP_') or i.startswith('DATA_'):
            print(repr({i: getattr(block, i)}))
    print()


if __name__ == "__main__":
    #
    print("test_block()")
    test_block()

