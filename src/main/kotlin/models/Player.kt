package models

import org.jetbrains.exposed.dao.*
import org.jetbrains.exposed.dao.id.EntityID

class Player(id: EntityID<Int>) : IntEntity(id) {
    companion object : IntEntityClass<Player>(PlayersTable)

    var accountId by PlayersTable.accountId
    var name by PlayersTable.name
    var level by PlayersTable.level
    var sex by PlayersTable.sex
    var vocation by PlayersTable.vocation
    var looktype by PlayersTable.looktype
    var lookhead by PlayersTable.lookhead
    var lookbody by PlayersTable.lookbody
    var looklegs by PlayersTable.looklegs
    var lookfeet by PlayersTable.lookfeet
    var lookaddons by PlayersTable.lookaddons
    var experience by PlayersTable.experience

    val account by Account referencedOn PlayersTable.accountId

    val vocationName: String
        get() = when (vocation) {
            0 -> "None"
            1 -> "Sorcerer"
            2 -> "Druid"
            3 -> "Paladin"
            4 -> "Knight"
            5 -> "Master Sorcerer"
            6 -> "Elder Druid"
            7 -> "Royal Paladin"
            8 -> "Elite Knight"
            else -> "Unknown"
        }
}