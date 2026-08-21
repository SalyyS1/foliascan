package com.salyvn.foliascan.report

import com.salyvn.foliascan.model.ScanReport
import kotlinx.serialization.json.Json

/** Machine-readable output for CI pipelines and dashboards. */
object JsonReporter {
    private val json = Json {
        prettyPrint = true
        encodeDefaults = true
    }

    fun render(report: ScanReport): String = json.encodeToString(report)
}
