package models

import org.jetbrains.exposed.dao.IntEntity
import org.jetbrains.exposed.dao.IntEntityClass
import org.jetbrains.exposed.dao.id.EntityID

class AccountToken(id: EntityID<Int>) : IntEntity(id) {
    companion object : IntEntityClass<AccountToken>(AccountTokenTable)

    var accountId by AccountTokenTable.accountId
    var createdAt by AccountTokenTable.createdAt
    var expiresAt by AccountTokenTable.expiresAt
    var token by AccountTokenTable.token
}