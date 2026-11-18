package io.papermc.paper.datacomponent

interface DataComponentHolder {
    fun setData(type: Any, value: Any)
    fun unsetData(type: Any)
    fun resetData(type: Any)
    fun copyDataFrom(source: DataComponentHolder, predicate: Any?)
}
