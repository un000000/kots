package models

import org.jetbrains.exposed.dao.id.IdTable
import org.jetbrains.exposed.dao.id.IntIdTable
import org.jetbrains.exposed.sql.javatime.datetime
import org.jetbrains.exposed.sql.javatime.timestamp

object AccountTokenTable : IntIdTable("account_token") {
    val accountId = reference("account_id", AccountsTable)
    val createdAt = datetime("created_at")
    val expiresAt = datetime("expires_at")
    val token = varchar("token", 64)
}

object AccountsTable : IntIdTable("accounts") {
    val name = varchar("name", 50).uniqueIndex()
    val email = varchar("email", 255).nullable()
    val password = varchar("password", 255)
    val premdays = integer("premdays").default(0)
    val lastday = integer("lastday").default(0)
}

object PlayersTable : IntIdTable("players") {
    val accountId = reference("account_id", AccountsTable)
    val name = varchar("name", 50).uniqueIndex()
    val level = integer("level").default(1)
    val sex = integer("sex").default(1)
    val vocation = integer("vocation").default(0)
    val looktype = integer("looktype").default(136)
    val lookhead = integer("lookhead").default(0)
    val lookbody = integer("lookbody").default(0)
    val looklegs = integer("looklegs").default(0)
    val lookfeet = integer("lookfeet").default(0)
    val lookaddons = integer("lookaddons").default(0)
    val experience = long("experience").default(0)
    val isreward = integer("isreward").nullable()
    val istutorial = integer("istutorial").nullable()
}

object PlayerOnlineTable : IdTable<Int>("players_online") {
    override val id = integer("player_id").entityId()
}

object BoostedCreatureTable : IntIdTable("boosted_creature") {
    val raceid = integer("raceid")
    val date = integer("date")
}

object BoostedBossTable : IntIdTable("boosted_boss") {
    val raceid = integer("raceid")
    val date = integer("date")
}