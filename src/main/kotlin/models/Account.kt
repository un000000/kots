package models

import org.jetbrains.exposed.dao.*
import org.jetbrains.exposed.dao.id.EntityID
import org.jetbrains.exposed.sql.transactions.transaction
import java.time.LocalDateTime
import kotlin.math.ceil
import kotlin.math.max

class Account(id: EntityID<Int>) : IntEntity(id) {
    companion object : IntEntityClass<Account>(AccountsTable)

    var name by AccountsTable.name
    var email by AccountsTable.email
    var password by AccountsTable.password
    var premdays by AccountsTable.premdays
    var lastday by AccountsTable.lastday

    val players by Player referrersOn PlayersTable.accountId

    val premiumDays: Int
        get() {
            val currentTime = System.currentTimeMillis() / 1000

            if (premdays == 0) return 0
            if (premdays == 65535) return 65535

            val currentDayOfYear = LocalDateTime.now().dayOfYear
            val currentYear = LocalDateTime.now().year
            val lastDayOfYear = LocalDateTime.ofEpochSecond(lastday.toLong(), 0, java.time.ZoneOffset.UTC).dayOfYear
            val lastYear = LocalDateTime.ofEpochSecond(lastday.toLong(), 0, java.time.ZoneOffset.UTC).year

            val daysPassed = currentDayOfYear + (365 * (currentYear - lastYear)) - lastDayOfYear
            val remainingDays = premdays - daysPassed

            return max(remainingDays, 0)
        }

    val isPremium: Boolean
        get() {
            val currentTime = System.currentTimeMillis() / 1000

            return premiumDays > 0
        }
}