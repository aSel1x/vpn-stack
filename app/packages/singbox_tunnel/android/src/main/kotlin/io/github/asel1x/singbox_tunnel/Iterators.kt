package io.github.asel1x.singbox_tunnel

import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.NetworkInterface as LibboxNetworkInterface

/**
 * gomobile cannot bind a Go slice, so every list crossing the boundary is an
 * iterator interface the host implements (sing-box v1.14.0
 * experimental/libbox/iterator.go:5).
 *
 * `len()` is answered honestly from a snapshot rather than returned as 0: the
 * Go side's own implementation returns the real length, and a caller that
 * trusted a lie would size a buffer wrongly.
 */
class StringArray(private val values: List<String>) : StringIterator {
    private val iterator = values.iterator()

    override fun len(): Int = values.size

    override fun hasNext(): Boolean = iterator.hasNext()

    override fun next(): String = iterator.next()
}

class InterfaceArray(private val values: List<LibboxNetworkInterface>) : NetworkInterfaceIterator {
    private val iterator = values.iterator()

    override fun hasNext(): Boolean = iterator.hasNext()

    override fun next(): LibboxNetworkInterface = iterator.next()
}
