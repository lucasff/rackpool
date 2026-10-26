package merkle

import (
	"strconv"
	"testing"
)

func TestProofsForEveryShape(t *testing.T) {
	for n := 1; n <= 40; n++ {
		leaves := make([]Hash, n)
		for i := range leaves {
			leaves[i] = Leaf([]byte(strconv.Itoa(i)))
		}
		root := Root(leaves)
		for i := range n {
			p := Proof(leaves, i)
			if !Verify(leaves[i], i, n, p, root) {
				t.Fatalf("n=%d i=%d: valid proof rejected", n, i)
			}
			if n > 1 && Verify(leaves[i], (i+1)%n, n, p, root) {
				t.Fatalf("n=%d i=%d: proof accepted at the wrong index", n, i)
			}
			if Verify(Leaf([]byte("forged")), i, n, p, root) {
				t.Fatalf("n=%d i=%d: forged leaf accepted", n, i)
			}
		}
	}
}
