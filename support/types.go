/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// support maps the definitions from headers in the C world into a nice go way
package support

// /*
// #include "./ebpf/types.h"
// #include "./ebpf/frametypes.h"
// */
// import "C"
import "fmt"

const (
	FrameMarkerUnknown  = 0
	FrameMarkerErrorBit = 1
	FrameMarkerPython   = 2
	FrameMarkerNative   = 3
	FrameMarkerPHP      = 4
	FrameMarkerPHPJIT   = 5
	FrameMarkerKernel   = 6
	FrameMarkerHotSpot  = 7
	FrameMarkerRuby     = 8
	FrameMarkerPerl     = 9
	FrameMarkerV8       = 10
	FrameMarkerAbort    = 11
)

const (
	ProgUnwindStop    = 0
	ProgUnwindNative  = 1
	ProgUnwindHotspot = 2
	ProgUnwindPython  = 3
	ProgUnwindPHP     = 4
	ProgUnwindRuby    = 5
	ProgUnwindPerl    = 6
	ProgUnwindV8      = 7
)

const (
	DeltaCommandFlag = 0

	MergeOpcodeNegative = 0
)

const (
	EventTypeGenericPID = 0
)

const MaxFrameUnwinds = 0

const (
	MetricIDBeginCumulative = 0
)

const (
	BitWidthPID  = 0
	BitWidthPage = 1
)

// EncodeBiasAndUnwindProgram encodes a bias_and_unwind_program value (for C.PIDPageMappingInfo)
// from a bias and unwind program values.
// This currently assumes a non-negative bias: this encoding may have to be changed if bias can be
// negative.
func EncodeBiasAndUnwindProgram(bias uint64,
	unwindProgram uint8) (uint64, error) {
	if (bias >> 56) > 0 {
		return 0, fmt.Errorf("unsupported bias value (too large): 0x%x", bias)
	}
	return bias | (uint64(unwindProgram) << 56), nil
}

// DecodeBiasAndUnwindProgram decodes the contents of the `bias_and_unwind_program` field in
// C.PIDPageMappingInfo and returns the corresponding bias and unwind program.
func DecodeBiasAndUnwindProgram(biasAndUnwindProgram uint64) (bias uint64, unwindProgram uint8) {
	bias = biasAndUnwindProgram & 0x00FFFFFFFFFFFFFF
	unwindProgram = uint8(biasAndUnwindProgram >> 56)
	return bias, unwindProgram
}

const (
	// CodedumpBytes holds the number of bytes of code to extract to userspace via codedump helper.
	// Needed for fsbase offset calculations.
	CodedumpBytes = 0
)

const (
	// StackDeltaBucket[Smallest|Largest] define the boundaries of the bucket sizes of the various
	// nested stack delta maps.
	StackDeltaBucketSmallest = 0
	StackDeltaBucketLargest  = 1

	// StackDeltaPage[Bits|Mask] determine the paging size of stack delta map information
	StackDeltaPageBits = 0
	StackDeltaPageMask = 1
)

const (
	HSTSIDIsStubBit       = 0
	HSTSIDHasFrameBit     = 1
	HSTSIDStackDeltaBit   = 2
	HSTSIDStackDeltaMask  = 3
	HSTSIDStackDeltaScale = 4
	HSTSIDSegMapBit       = 5
	HSTSIDSegMapMask      = 6
)

const (
	// PerfMaxStackDepth is the bpf map data array length for BPF_MAP_TYPE_STACK_TRACE traces
	PerfMaxStackDepth = 0
)
