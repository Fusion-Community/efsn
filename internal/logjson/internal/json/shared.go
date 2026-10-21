// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package json

import "reflect"

type Number string

func (n Number) String() string { return string(n) }

var numberType = reflect.TypeOf(Number(""))
