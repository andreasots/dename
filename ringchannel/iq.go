package ringchannel

// Copyright 2010 Kyle Lemons
// Copyright 2011 Google, Inc. (for changes on or after Feb. 22, 2011)
//
// The accompanying software is licensed under the Common Development and
// Distribution License, Version 1.0 (CDDL-1.0, the "License"); you may not use
// any part of this software except in compliance with the License.
//
// You may obtain a copy of the License at
//     http://opensource.org/licenses/CDDL-1.0
// More information about the CDDL can be found at
//     http://hub.opensolaris.org/bin/view/Main/licensing_faq

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
// License for the specific language governing permissions and limitations under
//the License.

type Ring struct {
	cnt, i int
	data   [][]byte
}

func (rb *Ring) Empty() bool {
	return rb.cnt == 0
}

func (rb *Ring) Peek() []byte {
	return rb.data[rb.i]
}

func (rb *Ring) Enqueue(x []byte) {
	if rb.cnt >= len(rb.data) {
		rb.grow(2*rb.cnt + 1)
	}
	rb.data[(rb.i+rb.cnt)%len(rb.data)] = x
	rb.cnt++
}

func (rb *Ring) Dequeue() {
	rb.cnt, rb.i = rb.cnt-1, (rb.i+1)%len(rb.data)
}

func (rb *Ring) grow(newSize int) {
	newData := make([][]byte, newSize)

	n := copy(newData, rb.data[rb.i:])
	copy(newData[n:], rb.data[:rb.cnt-n])

	rb.i = 0
	rb.data = newData
}

func RingIQ(in <-chan []byte, next chan<- []byte) {
	var rb Ring
	defer func() {
		for !rb.Empty() {
			next <- rb.Peek()
			rb.Dequeue()
		}
		close(next)
	}()

	for {
		if rb.Empty() {
			v, ok := <-in
			if !ok {
				return
			}
			rb.Enqueue(v)
		}

		select {
		case next <- rb.Peek():
			rb.Dequeue()
		case v, ok := <-in:
			if !ok {
				return
			}
			rb.Enqueue(v)
		}
	}
}
