package io.netty.channel

interface ChannelInboundHandler

open class ChannelInboundHandlerAdapter : ChannelInboundHandler {
    open fun channelRead(ctx: Any, msg: Any) {}
}
