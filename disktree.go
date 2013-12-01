package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const dbg = 0

func assert(flag bool) {
	if !flag {
		panic("assertion failed")
	}
}

func min(a int, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

type TreeError struct {
	msg string
}

func (err *TreeError) Error() string {
	return err.msg
}

type RadixTree struct {
	file    *os.File
	NrNodes int64
}


const HEADER_SIZE = 1024

type Header struct {
	NrNodes int64
	Root    int64
}

func (header *Header) Write(w io.Writer) error {
	err := binary.Write(w, binary.LittleEndian, header)
	if err != nil {
		return err
	}
	// pad
	_, err = w.Write(make([]byte, HEADER_SIZE-binary.Size(header)))
	return err
}

const KEY_BITS = 256
const HASH_BYTES = 32
const DATA_BYTES = 32
const ELEMENT_BITS = 4
const KEY_ELEMENTS = KEY_BITS / ELEMENT_BITS
const NODE_CHILDREN = 1 << ELEMENT_BITS

const NODE_SIZE = 1024

func Hash(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	hashVal := hash.Sum(make([]byte, 0))
	if dbg > 0 {
		fmt.Fprintf(os.Stdout, "Hash(%x) = %x\n", data, hashVal)
	}
	return hashVal
}

type LeafData struct {
	Hash     [HASH_BYTES]byte
	DataHash [HASH_BYTES]byte
}

type nodeData struct {
	Children    [NODE_CHILDREN]int64
	ChildHashes [NODE_CHILDREN][HASH_BYTES]byte
	LeafData
}

type diskNode struct {
	nodeData
	SubstringLength int64 // number of elements (i.e. in units of ELEMENT_BITS bits)
	KeySubstring    [KEY_BITS / 8]byte
}

type hashNode struct {
	Hash           []byte
	HasTwoChildren bool
}

type node struct {
	nodeData
	Index        int64
	KeyOffset    int
	KeySubstring []byte // slice of elements
	TreeHashes   *[NODE_CHILDREN-1]*hashNode
}

// hardcoded for ELEMENT_BITS = 4
func bytesToElements(bytes []byte) []byte {
	if ELEMENT_BITS != 4 {
		panic("not implemented")
	}
	elements := make([]byte, len(bytes)*2)
	for i, b := range bytes {
		elements[i*2] = b >> 4
		elements[i*2+1] = b & 0xf
	}
	return elements
}

// hardcoded for ELEMENT_BITS = 4
func elementsToBytes(elements []byte) []byte {
	if ELEMENT_BITS != 4 {
		panic("not implemented")
	}
	bytes := make([]byte, len(elements)/2)
	for i := range bytes {
		bytes[i] = elements[i*2]<<4 | elements[i*2+1]
	}
	if len(elements)%2 == 1 {
		bytes = append(bytes, elements[len(elements)-1]<<4)
	}
	return bytes
}

func (n *node) BuildTreeHashes(treeIx int) []byte {
	leafIx := treeIx - NODE_CHILDREN + 1
	if leafIx >= 0 {
		// leaf
		if n.Children[leafIx] > 0 {
			return n.ChildHashes[leafIx][:]
		} else {
			return make([]byte, 0)
		}
	} else {
		hn := &hashNode{Hash: make([]byte, 0)}
		for i := 0; i < 2; i++ {
			hn.Hash = append(hn.Hash, n.BuildTreeHashes(treeIx*2+1+i)...) // might be empty
		}
		if len(hn.Hash) > HASH_BYTES {
			// only hash if both children were non-empty
			hn.HasTwoChildren = true
			hn.Hash = Hash(hn.Hash)
		}
		n.TreeHashes[treeIx] = hn
		return hn.Hash
	}
}

func (n *node) EnsureTreeHashes() *[NODE_CHILDREN-1]*hashNode {
	if n.TreeHashes == nil {
		n.TreeHashes = new([NODE_CHILDREN-1]*hashNode)
		n.BuildTreeHashes(0)
	}
	return n.TreeHashes
}

// Indexes into the binary tree (row = depth, column = in-order index in row)
func (n *node) IndexHashNode(row int, column int) int {
	return (1 << uint(row)) - 1 + column
}

func (n *node) GetHashNode(index int) *hashNode {
	leafIx := index - NODE_CHILDREN + 1
	if leafIx >= 0 {
		return &hashNode{Hash: n.ChildHashes[leafIx][:]}
	}
	treeHashes := n.EnsureTreeHashes()
	return treeHashes[index]
}

func (n *node) SetChildHash(childIx int, hash []byte) {
	copy(n.ChildHashes[childIx][:], hash)
	n.TreeHashes = nil // invalidate
}

func (parent *node) SetChild(childIx int, child *node) {
	parent.Children[childIx] = child.Index
	// propagate hash
	if child.KeyOffset + len(child.KeySubstring) == KEY_ELEMENTS {
		// leaf
		parent.SetChildHash(childIx, child.Hash[:])
	} else {
		parent.SetChildHash(childIx, child.GetHashNode(child.IndexHashNode(0, 0)).Hash)
	}
}

func FromDisk(dn *diskNode, index int64, keyOffset int) *node {
	n := new(node)
	n.nodeData = dn.nodeData
	n.Index = index
	n.KeyOffset = keyOffset
	n.KeySubstring = bytesToElements(dn.KeySubstring[:])[:dn.SubstringLength]
	return n
}

func ToDisk(n *node) *diskNode {
	dn := new(diskNode)
	dn.nodeData = n.nodeData
	copy(dn.KeySubstring[:], elementsToBytes(n.KeySubstring))
	dn.SubstringLength = int64(len(n.KeySubstring))
	return dn
}

func (tree *RadixTree) Clear() error {
	_, err := tree.file.Seek(0, os.SEEK_SET)
	if err != nil {
		return err
	}
	var header Header
	header.NrNodes = 0
	header.Root = 0 // no root
	tree.NrNodes = 0
	err = header.Write(tree.file)
	if err != nil {
		return err
	}
	offset, err := tree.file.Seek(0, os.SEEK_CUR)
	if err != nil {
		return err
	}
	err = tree.file.Truncate(offset)
	return err
}

func NewRadixTree(file *os.File) (*RadixTree, error) {
	tree := &RadixTree{file, 0}
	header := new(Header)
	err := binary.Read(file, binary.LittleEndian, header)
	if err != nil {
		// Initialize file
		return tree, tree.Clear()
	} else {
		tree.NrNodes = header.NrNodes
		return tree, nil
	}
}

func (tree *RadixTree) readNode(nodeIx int64, keyOffset int) (*node, error) {
	dn := new(diskNode)
	_, err := tree.file.Seek(int64(HEADER_SIZE+NODE_SIZE*(nodeIx-1)), os.SEEK_SET)
	if err != nil {
		return nil, err
	}
	err = binary.Read(tree.file, binary.LittleEndian, dn)
	if err != nil {
		return nil, err
	}
	if dbg > 2 {
		fmt.Fprintf(os.Stdout, " read %x: %x\n", nodeIx, dn)
	}
	// debug check
	header, err := tree.readHeader()
	if err != nil {
		panic(err)
	}
	n := FromDisk(dn, nodeIx, keyOffset)
	for i, c := range n.Children {
		if c < 0 || c >= header.NrNodes + 1 {
			panic(fmt.Sprintf("child out of range: %x[%x]=%x", n.Index, i, c))
		}
	}
	return n, nil
}

func (tree *RadixTree) writeNode(node *node) error {
	if dbg > 2 {
		fmt.Fprintf(os.Stdout, " write %x: %x\n", node.Index, node)
	}
	_, err := tree.file.Seek(int64(HEADER_SIZE+NODE_SIZE*(node.Index-1)), os.SEEK_SET)
	if err != nil {
		return err
	}
	dn := ToDisk(node)
	err = binary.Write(tree.file, binary.LittleEndian, dn)
	if err != nil {
		return err
	}
	padding := NODE_SIZE - binary.Size(dn)
	_, err = tree.file.Write(make([]byte, padding))
	return err
}

func (tree *RadixTree) readHeader() (*Header, error) {
	_, err := tree.file.Seek(0, os.SEEK_SET)
	if err != nil {
		return nil, err
	}
	header := new(Header)
	err = binary.Read(tree.file, binary.LittleEndian, header)
	if err != nil {
		return nil, err
	}
	return header, nil
}

func (tree *RadixTree) writeHeader(header *Header) error {
	_, err := tree.file.Seek(0, os.SEEK_SET)
	if err != nil {
		return err
	}
	return binary.Write(tree.file, binary.LittleEndian, header)
}

func (tree *RadixTree) allocNode() (int64, error) {
	// read current number of nodes
	header, err := tree.readHeader()
	if err != nil {
		return -1, err
	}
	// get the new new node index
	header.NrNodes++
	newIndex := header.NrNodes
	// write back increased number of nodes
	err = tree.writeHeader(header)
	if err != nil {
		return -1, err
	}
	return newIndex, nil
}

// Note: doesn't write the node onto disk yet
func (tree *RadixTree) newNode(keyOffset int) (*node, error) {
	ix, err := tree.allocNode()
	if err != nil {
		return nil, err
	}
	n := &node{Index: ix, KeyOffset: keyOffset}
	return n, nil
}

func (tree *RadixTree) setRoot(node *node) error {
	header, err := tree.readHeader()
	if err != nil {
		return err
	}
	header.Root = node.Index
	return tree.writeHeader(header)
}

func (tree *RadixTree) getRoot() (*node, error) {
	header, err := tree.readHeader()
	if err != nil {
		return nil, err
	}
	if header.Root == 0 {
		return nil, nil
	} else {
		return tree.readNode(header.Root, 0)
	}
}

type SiblingHash struct {
	Hash          []byte
	KeyOffset     int
	IsLeftSibling bool // whether the hashed sibling was to the left of the original node on the path
}

type LookupResult struct {
	LeafData
	SiblingHashes []SiblingHash
}

func firstMismatch(slice1 []byte, slice2 []byte) int {
	shorterLen := min(len(slice1), len(slice2))
	for i := 0; i < shorterLen; i++ {
		if slice1[i] != slice2[i] {
			return i
		}
	}
	return shorterLen
}

// returns (nodes on matching path, position of last node, mismatch position in last node, error)
func (tree *RadixTree) partialLookup(key []byte) ([]*node, int, int, error) {
	if dbg > 1 {
		fmt.Fprintf(os.Stdout, "partialLookup(%x)\n", key)
	}
	n, err := tree.getRoot()
	if err != nil {
		return make([]*node, 0), 0, 0, err
	}
	if n == nil {
		return nil, 0, 0, nil
	}
	nodes := []*node{n}
	pos := 0
	for {
		mismatchPos := 0
		// First, compare the substring on the current n.
		if len(n.KeySubstring) > 0 {
			keySubstr := key[pos : pos+len(n.KeySubstring)]
			nodeSubstr := n.KeySubstring
			mismatchPos = firstMismatch(keySubstr, nodeSubstr)
			if mismatchPos != len(n.KeySubstring) {
				// Mismatch in the middle of the edge
				if dbg > 2 {
					fmt.Fprintf(os.Stdout, "partialLookup(%x) midsmatch %x+%x\n", key, pos, mismatchPos)
				}
				return nodes, pos, mismatchPos, nil
			}
			pos += len(n.KeySubstring)
			if pos == KEY_ELEMENTS {
				// Full match
				return nodes, KEY_ELEMENTS, 0, nil
			}
			if pos > KEY_ELEMENTS {
				return nil, 0, 0, &TreeError{"corrupted tree: key too long"}
			}
		}
		// Then, index into the children
		childIx := key[pos]
		if n.Children[childIx] == 0 {
			// Mismatch at the end of the edge
			if dbg > 2 {
				fmt.Fprintf(os.Stdout, "partialLookup(%x) endsmatch %x\n", key, pos)
			}
			return nodes, pos - len(n.KeySubstring), len(n.KeySubstring), nil
		} else {
			pos++
			n, err = tree.readNode(n.Children[childIx], pos)
			nodes = append(nodes, n)
			if err != nil {
				return nil, 0, 0, err
			}
		}
	}
}

func (tree *RadixTree) Lookup(keyBytes []byte) (*LookupResult, error) {
	key := bytesToElements(keyBytes)
	nodes, pos, _, err := tree.partialLookup(key)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 || pos != KEY_ELEMENTS {
		return nil, nil
	}
	pathHashes := make([]SiblingHash, 0)
	for i, n := range nodes {
		for j := 0; j < ELEMENT_BITS; j++ {
			keyIx := n.KeyOffset + len(n.KeySubstring)
			if keyIx == KEY_ELEMENTS {
				break
			}
			elem := key[keyIx]
			hnIx := n.IndexHashNode(j, int(elem>>uint(ELEMENT_BITS-j)))
			hashNode := n.GetHashNode(hnIx)
			if hashNode.HasTwoChildren {
				siblingSide := int(1 - ((elem >> uint(ELEMENT_BITS-j-1)) & 1))
				siblingNode := n.GetHashNode(hnIx * 2 + 1 + siblingSide)
				if dbg > 1 {
					side := 1 - siblingSide
					node := n.GetHashNode(hnIx * 2 + 1 + side)
					fmt.Fprintf(os.Stdout, "lookup %x/%x: %x %x %x !%4b[%x]=%x\n", keyBytes, i, hashNode, siblingNode, node, elem, j, siblingSide)
				}
				pathHashes = append(pathHashes, SiblingHash{
					KeyOffset: n.KeyOffset + j,
					Hash: siblingNode.Hash,
					IsLeftSibling: siblingSide == 0,
				})
			}
		}
	}
	result := &LookupResult{LeafData: nodes[len(nodes)-1].LeafData, SiblingHashes: pathHashes}
	return result, nil
}

func (tree *RadixTree) updatePath(path []*node) error {
	for {
		ix, err := tree.allocNode()
		if err != nil {
			return err
		}
		n := path[len(path)-1]
		oldix := n.Index
		n.Index = ix
		tree.writeNode(n)
		if len(path) == 1 {
			return tree.setRoot(n)
		} else {
			parent := path[len(path)-2]
			setChild := false
			for i, child := range parent.Children {
				if child == oldix {
					parent.SetChild(i, n)
					setChild = true
					break
				}
			}
			if !setChild {
				return &TreeError{"Inconsistent tree!"}
			}
			// continue with one node less
			path = path[:len(path)-1]
		}
	}
}

func (tree *RadixTree) Update(keyBytes []byte, data *LeafData) error {
	key := bytesToElements(keyBytes)
	nodes, pos, mismatchPos, err := tree.partialLookup(key)
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		// Create root node
		rootNode, err := tree.newNode(0)
		if err != nil {
			return err
		}
		rootNode.LeafData = *data
		rootNode.KeySubstring = key
		err = tree.writeNode(rootNode)
		if err != nil {
			return err
		}
		return tree.setRoot(rootNode)
	} else {
		lastNode := nodes[len(nodes)-1]
		if pos == KEY_ELEMENTS {
			// Update leaf node
			if dbg > 1 {
				fmt.Fprintf(os.Stdout, " update at %v+%v\n", pos, mismatchPos)
			}
			lastNode.LeafData = *data
		} else {
			// Make new child node
			newNode, err := tree.newNode(pos+mismatchPos+1)
			if err != nil {
				return err
			}
			newNode.KeySubstring = key[pos+mismatchPos+1:]
			newNode.LeafData = *data
			if mismatchPos == len(lastNode.KeySubstring) {
				if dbg > 1 {
					fmt.Fprintf(os.Stdout, " add at %v+%v\n", pos, mismatchPos)
				}
				lastNode.SetChild(int(key[pos+mismatchPos]), newNode)
			} else {
				if dbg > 1 {
					fmt.Fprintf(os.Stdout, " split at %v+%v\n", pos, mismatchPos)
				}
				// Split node: allocate second child node
				splitNode, err := tree.newNode(pos+mismatchPos+1)
				if err != nil {
					return err
				}
				oldSubstr := lastNode.KeySubstring
				mismatchedSubstr := oldSubstr[mismatchPos+1 : len(lastNode.KeySubstring)]
				splitNode.KeySubstring = mismatchedSubstr

				splitNode.LeafData = lastNode.LeafData
				lastNode.LeafData = LeafData{}
				copy(splitNode.Children[:], lastNode.Children[:])
				copy(splitNode.ChildHashes[:], lastNode.ChildHashes[:])
				copy(lastNode.Children[:], make([]int64, NODE_CHILDREN))
				copy(lastNode.ChildHashes[:], make([][HASH_BYTES]byte, NODE_CHILDREN))

				assert(oldSubstr[mismatchPos] != key[pos+mismatchPos])
				lastNode.SetChild(int(oldSubstr[mismatchPos]), splitNode)
				lastNode.SetChild(int(key[pos+mismatchPos]), newNode)

				lastNode.KeySubstring = oldSubstr[:mismatchPos]

				err = tree.writeNode(splitNode)
				if err != nil {
					return err
				}
			}
			err = tree.writeNode(newNode)
			if err != nil {
				return err
			}
		}
		return tree.updatePath(nodes)
	}
}

func (tree *RadixTree) GetRootHash() ([]byte, error) {
	n, err := tree.getRoot()
	if err != nil {
		return make([]byte, 0), err
	}
	if n == nil {
		// zero nodes
		return nil, nil
	} else if len(n.KeySubstring) == KEY_ELEMENTS {
		// one node
		return n.Hash[:], nil
	} else {
		// multiple nodes
		return n.GetHashNode(n.IndexHashNode(0, 0)).Hash, nil
	}
}

func (lookup *LookupResult) ComputeRootHash() []byte {
	if dbg > 0 {
		fmt.Fprintf(os.Stdout, "computing root hash\n")
	}
	hash := lookup.Hash[:]
	if dbg > 0 {
		fmt.Fprintf(os.Stdout, "leaf hash: %x\n", hash)
	}
	for i := len(lookup.SiblingHashes) - 1; i >= 0; i-- {
		siblingHash := lookup.SiblingHashes[i]
		if siblingHash.IsLeftSibling {
			if dbg > 0 {
				fmt.Fprintf(os.Stdout, "left: ")
			}
			hash = Hash(append(siblingHash.Hash, hash...))
		} else {
			if dbg > 0 {
				fmt.Fprintf(os.Stdout, "right: ")
			}
			hash = Hash(append(hash, siblingHash.Hash...))
		}
		if dbg > 1 {
			fmt.Fprintf(os.Stdout, "new hash: %x\n", hash)
		}
	}
	return hash
}

