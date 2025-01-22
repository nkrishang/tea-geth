// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
)

// precompiledTest defines the input/output pairs for precompiled contract tests.
type precompiledTest struct {
	Input, Expected string
	Gas             uint64
	Name            string
	NoBenchmark     bool // Benchmark primarily the worst-cases
}

// precompiledFailureTest defines the input/error pairs for precompiled
// contract failure tests.
type precompiledFailureTest struct {
	Input         string
	ExpectedError string
	Name          string
}

// allPrecompiles does not map to the actual set of precompiles, as it also contains
// repriced versions of precompiles at certain slots
var allPrecompiles = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}):    &ecrecover{},
	common.BytesToAddress([]byte{2}):    &sha256hash{},
	common.BytesToAddress([]byte{3}):    &ripemd160hash{},
	common.BytesToAddress([]byte{4}):    &dataCopy{},
	common.BytesToAddress([]byte{5}):    &bigModExp{eip2565: false},
	common.BytesToAddress([]byte{0xf5}): &bigModExp{eip2565: true},
	common.BytesToAddress([]byte{6}):    &bn256AddIstanbul{},
	common.BytesToAddress([]byte{7}):    &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{8}):    &bn256PairingGranite{},
	common.BytesToAddress([]byte{9}):    &blake2F{},
	common.BytesToAddress([]byte{0x0a}): &kzgPointEvaluation{},
	common.BytesToAddress([]byte{0xed}): &gpgVerify{},

	common.BytesToAddress([]byte{0x01, 0x00}): &p256Verify{},

	common.BytesToAddress([]byte{0x0f, 0x0a}): &bls12381G1Add{},
	common.BytesToAddress([]byte{0x0f, 0x0b}): &bls12381G1Mul{},
	common.BytesToAddress([]byte{0x0f, 0x0c}): &bls12381G1MultiExp{},
	common.BytesToAddress([]byte{0x0f, 0x0d}): &bls12381G2Add{},
	common.BytesToAddress([]byte{0x0f, 0x0e}): &bls12381G2Mul{},
	common.BytesToAddress([]byte{0x0f, 0x0f}): &bls12381G2MultiExp{},
	common.BytesToAddress([]byte{0x0f, 0x10}): &bls12381Pairing{},
	common.BytesToAddress([]byte{0x0f, 0x11}): &bls12381MapG1{},
	common.BytesToAddress([]byte{0x0f, 0x12}): &bls12381MapG2{},
}

// EIP-152 test vectors
var blake2FMalformedInputTests = []precompiledFailureTest{
	{
		Input:         "",
		ExpectedError: errBlake2FInvalidInputLength.Error(),
		Name:          "vector 0: empty input",
	},
	{
		Input:         "00000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
		ExpectedError: errBlake2FInvalidInputLength.Error(),
		Name:          "vector 1: less than 213 bytes input",
	},
	{
		Input:         "000000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
		ExpectedError: errBlake2FInvalidInputLength.Error(),
		Name:          "vector 2: more than 213 bytes input",
	},
	{
		Input:         "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000002",
		ExpectedError: errBlake2FInvalidFinalFlag.Error(),
		Name:          "vector 3: malformed final block indicator flag",
	},
}

func testPrecompiled(addr string, test precompiledTest, t *testing.T) {
	p := allPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	gas := p.RequiredGas(in)
	t.Run(fmt.Sprintf("%s-Gas=%d", test.Name, gas), func(t *testing.T) {
		if res, _, err := RunPrecompiledContract(p, in, gas, nil); err != nil {
			t.Error(err)
		} else if common.Bytes2Hex(res) != test.Expected {
			t.Errorf("Expected %v, got %v", test.Expected, common.Bytes2Hex(res))
		}
		if expGas := test.Gas; expGas != gas {
			t.Errorf("%v: gas wrong, expected %d, got %d", test.Name, expGas, gas)
		}
		// Verify that the precompile did not touch the input buffer
		exp := common.Hex2Bytes(test.Input)
		if !bytes.Equal(in, exp) {
			t.Errorf("Precompiled %v modified input data", addr)
		}
	})
}

func testPrecompiledOOG(addr string, test precompiledTest, t *testing.T) {
	p := allPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	gas := p.RequiredGas(in) - 1

	t.Run(fmt.Sprintf("%s-Gas=%d", test.Name, gas), func(t *testing.T) {
		_, _, err := RunPrecompiledContract(p, in, gas, nil)
		if err.Error() != "out of gas" {
			t.Errorf("Expected error [out of gas], got [%v]", err)
		}
		// Verify that the precompile did not touch the input buffer
		exp := common.Hex2Bytes(test.Input)
		if !bytes.Equal(in, exp) {
			t.Errorf("Precompiled %v modified input data", addr)
		}
	})
}

func testPrecompiledFailure(addr string, test precompiledFailureTest, t *testing.T) {
	p := allPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	gas := p.RequiredGas(in)
	t.Run(test.Name, func(t *testing.T) {
		_, _, err := RunPrecompiledContract(p, in, gas, nil)
		if err.Error() != test.ExpectedError {
			t.Errorf("Expected error [%v], got [%v]", test.ExpectedError, err)
		}
		// Verify that the precompile did not touch the input buffer
		exp := common.Hex2Bytes(test.Input)
		if !bytes.Equal(in, exp) {
			t.Errorf("Precompiled %v modified input data", addr)
		}
	})
}

func benchmarkPrecompiled(addr string, test precompiledTest, bench *testing.B) {
	if test.NoBenchmark {
		return
	}
	p := allPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	reqGas := p.RequiredGas(in)

	var (
		res  []byte
		err  error
		data = make([]byte, len(in))
	)

	bench.Run(fmt.Sprintf("%s-Gas=%d", test.Name, reqGas), func(bench *testing.B) {
		bench.ReportAllocs()
		start := time.Now()
		bench.ResetTimer()
		for i := 0; i < bench.N; i++ {
			copy(data, in)
			res, _, err = RunPrecompiledContract(p, data, reqGas, nil)
		}
		bench.StopTimer()
		elapsed := uint64(time.Since(start))
		if elapsed < 1 {
			elapsed = 1
		}
		gasUsed := reqGas * uint64(bench.N)
		bench.ReportMetric(float64(reqGas), "gas/op")
		// Keep it as uint64, multiply 100 to get two digit float later
		mgasps := (100 * 1000 * gasUsed) / elapsed
		bench.ReportMetric(float64(mgasps)/100, "mgas/s")
		//Check if it is correct
		if err != nil {
			bench.Error(err)
			return
		}
		if common.Bytes2Hex(res) != test.Expected {
			bench.Errorf("Expected %v, got %v", test.Expected, common.Bytes2Hex(res))
			return
		}
	})
}

// Benchmarks the sample inputs from the ECRECOVER precompile.
func BenchmarkPrecompiledEcrecover(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "000000000000000000000000ceaccac640adf55b2028469bd36ba501f28b699d",
		Name:     "",
	}
	benchmarkPrecompiled("01", t, bench)
}

// Benchmarks the sample inputs from the SHA256 precompile.
func BenchmarkPrecompiledSha256(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "811c7003375852fabd0d362e40e68607a12bdabae61a7d068fe5fdd1dbbf2a5d",
		Name:     "128",
	}
	benchmarkPrecompiled("02", t, bench)
}

// Benchmarks the sample inputs from the RIPEMD precompile.
func BenchmarkPrecompiledRipeMD(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "0000000000000000000000009215b8d9882ff46f0dfde6684d78e831467f65e6",
		Name:     "128",
	}
	benchmarkPrecompiled("03", t, bench)
}

// Benchmarks the sample inputs from the identity precompile.
func BenchmarkPrecompiledIdentity(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Name:     "128",
	}
	benchmarkPrecompiled("04", t, bench)
}

// Tests the sample inputs from the ModExp EIP 198.
func TestPrecompiledModExp(t *testing.T)      { testJson("modexp", "05", t) }
func BenchmarkPrecompiledModExp(b *testing.B) { benchJson("modexp", "05", b) }

func TestPrecompiledModExpEip2565(t *testing.T)      { testJson("modexp_eip2565", "f5", t) }
func BenchmarkPrecompiledModExpEip2565(b *testing.B) { benchJson("modexp_eip2565", "f5", b) }

// Tests the sample inputs from the elliptic curve addition EIP 213.
func TestPrecompiledBn256Add(t *testing.T)      { testJson("bn256Add", "06", t) }
func BenchmarkPrecompiledBn256Add(b *testing.B) { benchJson("bn256Add", "06", b) }

// Tests OOG
func TestPrecompiledModExpOOG(t *testing.T) {
	modexpTests, err := loadJson("modexp")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range modexpTests {
		testPrecompiledOOG("05", test, t)
	}
}

// Tests the sample inputs from the elliptic curve scalar multiplication EIP 213.
func TestPrecompiledBn256ScalarMul(t *testing.T)      { testJson("bn256ScalarMul", "07", t) }
func BenchmarkPrecompiledBn256ScalarMul(b *testing.B) { benchJson("bn256ScalarMul", "07", b) }

// Tests the sample inputs from the elliptic curve pairing check EIP 197.
func TestPrecompiledBn256Pairing(t *testing.T)      { testJson("bn256Pairing", "08", t) }
func BenchmarkPrecompiledBn256Pairing(b *testing.B) { benchJson("bn256Pairing", "08", b) }

func TestPrecompiledBlake2F(t *testing.T)      { testJson("blake2F", "09", t) }
func BenchmarkPrecompiledBlake2F(b *testing.B) { benchJson("blake2F", "09", b) }

func TestPrecompileBlake2FMalformedInput(t *testing.T) {
	for _, test := range blake2FMalformedInputTests {
		testPrecompiledFailure("09", test, t)
	}
}

func TestPrecompileBn256PairingTooLargeInput(t *testing.T) {
	big := make([]byte, params.Bn256PairingMaxInputSizeGranite+1)
	testPrecompiledFailure("08", precompiledFailureTest{
		Input:         common.Bytes2Hex(big),
		ExpectedError: "bad elliptic curve pairing input size",
		Name:          "bn256Pairing_input_too_big",
	}, t)
}

func TestPrecompiledEcrecover(t *testing.T) { testJson("ecRecover", "01", t) }

func testJson(name, addr string, t *testing.T) {
	tests, err := loadJson(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		testPrecompiled(addr, test, t)
	}
}

func testJsonFail(name, addr string, t *testing.T) {
	tests, err := loadJsonFail(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		testPrecompiledFailure(addr, test, t)
	}
}

func benchJson(name, addr string, b *testing.B) {
	tests, err := loadJson(name)
	if err != nil {
		b.Fatal(err)
	}
	for _, test := range tests {
		benchmarkPrecompiled(addr, test, b)
	}
}

func TestPrecompiledBLS12381G1Add(t *testing.T)      { testJson("blsG1Add", "f0a", t) }
func TestPrecompiledBLS12381G1Mul(t *testing.T)      { testJson("blsG1Mul", "f0b", t) }
func TestPrecompiledBLS12381G1MultiExp(t *testing.T) { testJson("blsG1MultiExp", "f0c", t) }
func TestPrecompiledBLS12381G2Add(t *testing.T)      { testJson("blsG2Add", "f0d", t) }
func TestPrecompiledBLS12381G2Mul(t *testing.T)      { testJson("blsG2Mul", "f0e", t) }
func TestPrecompiledBLS12381G2MultiExp(t *testing.T) { testJson("blsG2MultiExp", "f0f", t) }
func TestPrecompiledBLS12381Pairing(t *testing.T)    { testJson("blsPairing", "f10", t) }
func TestPrecompiledBLS12381MapG1(t *testing.T)      { testJson("blsMapG1", "f11", t) }
func TestPrecompiledBLS12381MapG2(t *testing.T)      { testJson("blsMapG2", "f12", t) }

func TestPrecompiledPointEvaluation(t *testing.T) { testJson("pointEvaluation", "0a", t) }

func BenchmarkPrecompiledPointEvaluation(b *testing.B) { benchJson("pointEvaluation", "0a", b) }

func BenchmarkPrecompiledBLS12381G1Add(b *testing.B)      { benchJson("blsG1Add", "f0a", b) }
func BenchmarkPrecompiledBLS12381G1Mul(b *testing.B)      { benchJson("blsG1Mul", "f0b", b) }
func BenchmarkPrecompiledBLS12381G1MultiExp(b *testing.B) { benchJson("blsG1MultiExp", "f0c", b) }
func BenchmarkPrecompiledBLS12381G2Add(b *testing.B)      { benchJson("blsG2Add", "f0d", b) }
func BenchmarkPrecompiledBLS12381G2Mul(b *testing.B)      { benchJson("blsG2Mul", "f0e", b) }
func BenchmarkPrecompiledBLS12381G2MultiExp(b *testing.B) { benchJson("blsG2MultiExp", "f0f", b) }
func BenchmarkPrecompiledBLS12381Pairing(b *testing.B)    { benchJson("blsPairing", "f10", b) }
func BenchmarkPrecompiledBLS12381MapG1(b *testing.B)      { benchJson("blsMapG1", "f11", b) }
func BenchmarkPrecompiledBLS12381MapG2(b *testing.B)      { benchJson("blsMapG2", "f12", b) }

// Failure tests
func TestPrecompiledBLS12381G1AddFail(t *testing.T)      { testJsonFail("blsG1Add", "f0a", t) }
func TestPrecompiledBLS12381G1MulFail(t *testing.T)      { testJsonFail("blsG1Mul", "f0b", t) }
func TestPrecompiledBLS12381G1MultiExpFail(t *testing.T) { testJsonFail("blsG1MultiExp", "f0c", t) }
func TestPrecompiledBLS12381G2AddFail(t *testing.T)      { testJsonFail("blsG2Add", "f0d", t) }
func TestPrecompiledBLS12381G2MulFail(t *testing.T)      { testJsonFail("blsG2Mul", "f0e", t) }
func TestPrecompiledBLS12381G2MultiExpFail(t *testing.T) { testJsonFail("blsG2MultiExp", "f0f", t) }
func TestPrecompiledBLS12381PairingFail(t *testing.T)    { testJsonFail("blsPairing", "f10", t) }
func TestPrecompiledBLS12381MapG1Fail(t *testing.T)      { testJsonFail("blsMapG1", "f11", t) }
func TestPrecompiledBLS12381MapG2Fail(t *testing.T)      { testJsonFail("blsMapG2", "f12", t) }

func loadJson(name string) ([]precompiledTest, error) {
	data, err := os.ReadFile(fmt.Sprintf("testdata/precompiles/%v.json", name))
	if err != nil {
		return nil, err
	}
	var testcases []precompiledTest
	err = json.Unmarshal(data, &testcases)
	return testcases, err
}

func loadJsonFail(name string) ([]precompiledFailureTest, error) {
	data, err := os.ReadFile(fmt.Sprintf("testdata/precompiles/fail-%v.json", name))
	if err != nil {
		return nil, err
	}
	var testcases []precompiledFailureTest
	err = json.Unmarshal(data, &testcases)
	return testcases, err
}

// BenchmarkPrecompiledBLS12381G1MultiExpWorstCase benchmarks the worst case we could find that still fits a gaslimit of 10MGas.
func BenchmarkPrecompiledBLS12381G1MultiExpWorstCase(b *testing.B) {
	task := "0000000000000000000000000000000008d8c4a16fb9d8800cce987c0eadbb6b3b005c213d44ecb5adeed713bae79d606041406df26169c35df63cf972c94be1" +
		"0000000000000000000000000000000011bc8afe71676e6730702a46ef817060249cd06cd82e6981085012ff6d013aa4470ba3a2c71e13ef653e1e223d1ccfe9" +
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
	input := task
	for i := 0; i < 4787; i++ {
		input = input + task
	}
	testcase := precompiledTest{
		Input:       input,
		Expected:    "0000000000000000000000000000000005a6310ea6f2a598023ae48819afc292b4dfcb40aabad24a0c2cb6c19769465691859eeb2a764342a810c5038d700f18000000000000000000000000000000001268ac944437d15923dc0aec00daa9250252e43e4b35ec7a19d01f0d6cd27f6e139d80dae16ba1c79cc7f57055a93ff5",
		Name:        "WorstCaseG1",
		NoBenchmark: false,
	}
	benchmarkPrecompiled("f0c", testcase, b)
}

// BenchmarkPrecompiledBLS12381G2MultiExpWorstCase benchmarks the worst case we could find that still fits a gaslimit of 10MGas.
func BenchmarkPrecompiledBLS12381G2MultiExpWorstCase(b *testing.B) {
	task := "000000000000000000000000000000000d4f09acd5f362e0a516d4c13c5e2f504d9bd49fdfb6d8b7a7ab35a02c391c8112b03270d5d9eefe9b659dd27601d18f" +
		"000000000000000000000000000000000fd489cb75945f3b5ebb1c0e326d59602934c8f78fe9294a8877e7aeb95de5addde0cb7ab53674df8b2cfbb036b30b99" +
		"00000000000000000000000000000000055dbc4eca768714e098bbe9c71cf54b40f51c26e95808ee79225a87fb6fa1415178db47f02d856fea56a752d185f86b" +
		"000000000000000000000000000000001239b7640f416eb6e921fe47f7501d504fadc190d9cf4e89ae2b717276739a2f4ee9f637c35e23c480df029fd8d247c7" +
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
	input := task
	for i := 0; i < 1040; i++ {
		input = input + task
	}

	testcase := precompiledTest{
		Input:       input,
		Expected:    "0000000000000000000000000000000018f5ea0c8b086095cfe23f6bb1d90d45de929292006dba8cdedd6d3203af3c6bbfd592e93ecb2b2c81004961fdcbb46c00000000000000000000000000000000076873199175664f1b6493a43c02234f49dc66f077d3007823e0343ad92e30bd7dc209013435ca9f197aca44d88e9dac000000000000000000000000000000000e6f07f4b23b511eac1e2682a0fc224c15d80e122a3e222d00a41fab15eba645a700b9ae84f331ae4ed873678e2e6c9b000000000000000000000000000000000bcb4849e460612aaed79617255fd30c03f51cf03d2ed4163ca810c13e1954b1e8663157b957a601829bb272a4e6c7b8",
		Name:        "WorstCaseG2",
		NoBenchmark: false,
	}
	benchmarkPrecompiled("f0f", testcase, b)
}

// Benchmarks the sample inputs from the P256VERIFY precompile.
func BenchmarkPrecompiledP256Verify(bench *testing.B) {
	t := precompiledTest{
		Input:    "4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e",
		Expected: "0000000000000000000000000000000000000000000000000000000000000001",
		Name:     "p256Verify",
	}
	benchmarkPrecompiled("100", t, bench)
}

func TestPrecompiledP256Verify(t *testing.T) { testJson("p256Verify", "100", t) }

// Tests the GPG Ed25519 signature verification. Input format: abi.encodePacked(message.len, message, pubKey.len, pubKey, sig.len, sig)
func TestPrecompiledGpgEd25519Verify(t *testing.T) { testJson("gpgEd25519Verify", "ed", t) }

func BenchmarkPrecompiledGpgEd25519Verify(b *testing.B) {
	t := precompiledTest{
		Input:    "5af06adaf66d4711487c062b6d213c163973294ff7b0d532289274c566b57bb449ceb217b43f23780000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000026000000000000000000000000000000000000000000000000000000000000001af9833046768354e16092b06010401da470f0101074089ea06d9820134822b9ddaeef1929c50ddfd9bbcf7c0794f3082d864fecb30feb42f5a616368204f62726f6e7420287465612d676574682d7465737429203c7a6f62726f6e7440676d61696c2e636f6d3e88930413160a003b162104c4e971386f7e24899b765c6b49ceb217b43f237805026768354e021b03050b0908070202220206150a09080b020416020301021e07021780000a091049ceb217b43f2378e65600ff538b73b85fc29fe716c0857343ac1efb4ac2864fd346de79f00d0e0f6d6e8e970100cdaf800a4ea1c9fabe8c982a191bff567c16019dad016c06e643b689ff3fd60eb838046768354e120a2b060104019755010501010740cf010ab1e65c0a4560292d4f8faaf2c03b6e115f2482464404d12bed986c8f530301080788780418160a0020162104c4e971386f7e24899b765c6b49ceb217b43f237805026768354e021b0c000a091049ceb217b43f237866a900fe2d50d10d916ced462d925220880b538cc9ab4fde817aa5bb3928d4f2a46003a50100d420071637d56defa999a22bc43bf0b0b179cf288d9643a54e98c13eb346df0a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007788750400160a001d162104c4e971386f7e24899b765c6b49ceb217b43f23780502678fee15000a091049ceb217b43f237896b40100f52ea02d10938943be614b37cdfb88e50747369bd0ee9fef045db0ff707ca90f00fe3e44932659240c78c30b880eb479a1e6dfada998d7e6f8868ef00eb4dc3dd000000000000000000000",
		Expected: "0000000000000000000000000000000000000000000000000000000000000001",
		Name:     "verify_gpg_ed25519_zach_signed",
	}
	benchmarkPrecompiled("ed", t, b)
}

func BenchmarkPrecompiledGpgRSAVerify(b *testing.B) {
	t := precompiledTest{
		Input:    "8d36183ef046bbd47bdaf0974f44afb4a4cfe0ec3b63bb1b06338f1bc0deb0974c4c3ab789f86a6f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000098000000000000000000000000000000000000000000000000000000000000008ce99020d04678fd745011000d6a2e19ddb1d378fdf58bd6c231dc7c5d1db60ad5aa8a6cc0c1cf2a8881adeccadbbdfa0148aa32885972d2f02033097a771c9f2b309c12aed7807b084334c1b9238458a692e819bb8a2c9ec40e5ab19055116bf4fe77b8c00f2481131c46645eaffae7ae6d767b9e3aa7eb34f446d21faabc38ec55f0f37accade05fe00e2f7e7ba97a98fb198255a4cd222964d2c0c3f129ce155692d8233f32afb016df1c72c3d9fa7c04f2ff30adebc830dcbdec77c38b2540c0b11dde2a246022ccce7e917fb9fe6b18a3a81e5a7b3be550eefd240fc87261e777e527363d4fd72e84ba6e0138903de95a2177c173f0df97858f202301021b776abb925e70b59e752a0f5b4e374cbf72ed81e8f0ce43ca3b996fc92f68d532de133f77cb2d24b91a70e7a4f9217d31581d871ee7e9107ee178b27d2a31816e845b1f7bc189df648e03a07f4886a0d332e84df9ff81857cda725f762f384ab8984ee29e5cebb676c880945ab7d54c83b92a0dec87d790320e10198c62cd68cc78273b198347d5532c5f4bf14a8c761e81ae97f66f57f0782d6a3d426b482ef93dec7fc3b7f4d08f526a4dc660f19399ec0a1debea7538b900b74d913164f75df383b9a2bfc3b3e526dded8d6bd505e3a68f41629dbc8473d49e2bafa1730aafd71c92284de7563141cc58f2fdcd1815f903ed315ad1483aad5682ef8e88cf21f034c47d92d40ab8398904b0011010001b41f5a616368204f62726f6e74203c7a6f62726f6e7440676d61696c2e636f6d3e89025104130108003b162104fd22037dffd75189a0399b084c4c3ab789f86a6f0502678fd745021b03050b0908070202220206150a09080b020416020301021e07021780000a09104c4c3ab789f86a6fc4050ffe3c79d78ca987329fb699647ef2d7991bcdf42f467fe9532657e7b409dab1032ae96dbcf4315bfa096c5bd4161be10f57e679276ae9e10eb02bed8f5c39a548f695a4f96347de201bb4882d731149c783aa7b0ec4ab92ff595c64527ff86cb9132ea0ec2df6e2170239523639ad4665b0ed48d5dec9967895517f54797d3d8f5c12c952e38cd2002e699d0bdf587b048d75371be233684710c1f06b854d46f18c6308d7b6e1a3230afd2856599c594f50434464541b0e6306d7afdfcaa127832525e65d67f1bb4192ed47fe3c0275fbbc8bf2d73997b12d4ef1c18cd63ca571bf73d6e71e971c5f018acb537ac4d2e4fcdb39de9e78cd1b8a140b9ce703452c6d5c569e25a83b5e9bdd2e3d314557f02b45ff2d3b933d2a5610d14b6f670aeac1c3b75be559bc800533120296fa467297f5c84edcfae1dd34cffce6802e47c7baf1b4a4264768fda65166f7b88bc412144710a849cce0759adbae21aef5f7340933877a42408132f24e37f593fe2ee29287a36bfbef83e5ef028e51958ac55996372a1e5b02ed02b63bfd60bd40af8c9728d3a2527102a9d6b872afbaaf0c4273009496aea5868957b9d37727f57610943491ab96a542aa0387de7796fff0d64aa73fa0d272a79b1543dfdf1f063413b0326a9b90065e3a45a03768cf60b49a9453171a8478b5faea86014ebd43f70253584acc3a83389b964dcbbc7a768d9d8fb9020d04678fd745011000d9b191215c1834fadd6eb0ee86470444ce08a8606fc91bb51507ce634364190116a0eaed2771d22b96b7d5b20b784e49b1ea5d341950c14bacc6b2e62df8d150cdeff991075204ab6014315868551237c247d33cf0d2e66e72ae3c0d173fede1ed7a59c63a1e9d80bbc04de79304625cd05748c0bb773879450e1a7c663838bdb56465ff417cf9c97aa801698baa0bb2a098b24923322dc1e42c34cc8ec3dcd2fda39b43294bc0a91be1c7772b8d71547cc4755d793d2f4c3dfb1abea9ea45a8b9899e2ab763392cf84d5f462adabf9f2a0d9c87db537702aaacbb445a2a91e43b6e5c02b8d877f340434115997846b7a3ae419f1307a2cbcf9c0c85c7733dae540c746ea62aef40493aa1b7b581e7f9e6b63cdfaf8847003429c1bf1e5733a1ec38be7a360f98053b86e43efe1de87735924f5fdf6b4718ef4203d80901039818fad0e68fd435536fde8d569d6c262b571e8e224c959225146b6dfee2734a23122a420bf2f6624b53cc7582e07d0ec1483fb6256bcc2367681ec8ce93ea685bdd3f4539e3e7ef19cfe95dcd23c5c9bc004a9517bbf8142febb02b1f6415e37361b1a3bf0a1f2b47edb1e5457cabe93e71ac97b50ab48a2d276b2ff6e4a13d4a7204ff3f0d36275f0952300f7d88557a74a92ff3c573cc57a419dfb3ad7d0767fee980db6bb1af84573a048a6e1ec7a88b98a8655f7a62a190fa5fb75dfee6070011010001890236041801080020162104fd22037dffd75189a0399b084c4c3ab789f86a6f0502678fd745021b0c000a09104c4c3ab789f86a6fd6101000b5248d88e035b6d0c18777f98e11451dc37cc441840038968ce3d50f183be21056a65f57486ae6b0d23723a70e4beb2e1f9424cd5400936e9398e0193098b39219e183c9d58e333119f9d0d84c376285807e98e3b80501dbf9636b0a05c5150c8086ee4cd5c5c9dae504bebcb0210f394b3daa5962981c7d48036811d2957b02acfdc04d39cb4b3f035969386d547f96f751baa1949b09e4420b4788bd50e270233c58ba61cb5ab63b4ef85ce9f35e183175b1892f506f905944b425e22697cdcde93c20307537ca2e651469f3240dd642e6062952b7bbf4b7c6a57d0b8de20fba9e2fce7cd1c664d529a1a2adb660c4ac696f9c3cdec6018931639ceb314c703e3391ec9e2b65ffba440126b6b2f17c3f98d3c97c5a57f3792e2df940ab6b30da3d51d8daf25a56d1df8026bd38da903849d0dfb654d7e35e46f0a493a3815e03e3bb4070574eda87f39672b198699ead436dacb2cd3a9e45dfaacc051c517267054202458d944932ec9c3845555ae31748bd29967112f9b6768c300e9a566aa0f337510e7fbd94edaa8fbc18f7095bc16847e0cf8be26b805ac9e3a8c33d278b1baee4e6857fcbdaf85744a4914605df28ee4a0d5495af7a604127a9e8b04411999e10926338073c9d4a9bfa89f2bf4e6bd3a3a7319fb788e0551d4be38a38dbcf0767d398ec3d232995b2f814713a12be50409c0a5dcf25a450f0954da453000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000023689023304000108001d162104fd22037dffd75189a0399b084c4c3ab789f86a6f0502678fede6000a09104c4c3ab789f86a6f65760fff6e9f5a7b79b0a6b703e0b4ced6677461626f0f8dbe59bfd2c3b3b8db53e9077b972c1202567d2a28817e0e4f0b6944808aedb0b430c606c7267679bdb97c3af554684cd36065c84567e0c1e9c4a251f7de89e4e7c167307a29e3a63352243d48fc8d7375b861462e03a66e7be075edd1be586ef7c27bf634b96b9a4945d67504f29b3fa2292de37b6680829cdcd956ba11b571311adaf3598e145eee0ca1612f3a7014005e6403d231129d03240bc6273e835ba227bfad89de650fcc63f392128080a3f01e8b51f9c22ed1b92fdadb9581292e26e582f2017c5e94423a6f804f47f280c881e42a776abf26ddbc4d5b21a23e88bc78c6e1f811a064e5e5d4f77771518d64856eb88fb55b7560441ac1f99abae48bb3cd172e4e002f4297fbf53bec4b131aa9318e5b3811738ba885bd76b99368eb706380603c2161c1e5efb5918662816b86823029aa3f0a7f0159922bcb1188169d4f4ceebd0b274f210a1adbd4f8542800c3df8885e9fd55ec4d9af9637d944d99c68b37e568c5009bdfb63e1e6900bc55996150947b31b18bf2c4a8eea5454c67767f50371a0702ca8e26e8fd74076cf5a0e149d890537af1afd06954dd44892768145ed92dc98012b1ef28101d2694afe511a77e02caedaa9522b0263adbe9cd188222f4dda3db15c699d04148f3706d92484c339c12456f9d39f99d7e2d0b1e4f21152f776d2ccaddc1bc00000000000000000000",
		Expected: "0000000000000000000000000000000000000000000000000000000000000001",
		Name:     "verify_gpg_rsa_zach_signed",
	}
	benchmarkPrecompiled("ed", t, b)
}

// Tests GPG Ed25519 verification with malformed inputs
var gpgEd25519MalformedInputTests = []precompiledFailureTest{
	{
		Input:         "",
		ExpectedError: "failed to decode input",
		Name:          "empty input",
	},
	{
		Input:         "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000024",
		ExpectedError: "failed to decode input",
		Name:          "input less than 96 bytes",
	},
	{
		Input:         "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000001ab984404676a5d0e16092b06010401da470f010107405d10ab19030f8a3edcace13d0e166367d295f1e114ef87c8f3009cda931a0eebb42b4b72697368616e67204e61646761756461203c6b72697368616e672e6e6f746540676d61696c2e636f6d3e88930413160a003b162104c0c2dcd8a10746e47c75b181967672f8454443b80502676a5d0e021b03050b0908070202220206150a09080b020416020301021e07021780000a0910967672f8454443b8224200ff75c455a94fe4c82e6c516f523aec19d42857f17a74e1c7402401540f9ed70c1d00fe2a2e4e3f5a136084bcb5aa5f68e8995a75bf8d0a93cc024509e4156443b35004b83804676a5d0e120a2b060104019755010501010740151340eabbaaf90a7dda8562b821742d068d1a41681d7e152eefbf73042ca32e0301080788780418160a0020162104c0c2dcd8a10746e47c75b181967672f8454443b80502676a5d0e021b0c000a0910967672f8454443b8d9480100fda1c358442e155612fe0af757f2eeb94fea65d9f90ddaa57bab37683890c19f00fc09cf6e07b238f81361edb9cc119fc876b95f68aa001d8308d53d8f3f99dcfc22000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007788750400160a001d162104c0c2dcd8a10746e47c75b181967672f8454443b80502676e9c52000a0910967672f8454443b8c10000fe22cd5d6fd453b2bad46641bc41ffb3cffa834a2c74da517e8fb644e1631d23b50100828ee409948c1ea870d2192c3a76cbeb46556454f20d132f52dfe835dfb9ad04000000000000000000",
		ExpectedError: "invalid public key",
		Name:          "invalid public key",
	},
}

func TestPrecompiledGpgEd25519VerifyMalformedInput(t *testing.T) {
	for _, test := range gpgEd25519MalformedInputTests {
		testPrecompiledFailure("ed", test, t)
	}
}
