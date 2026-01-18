package plugins

import org.jetbrains.exposed.sql.*

fun configureDatabases() {
    val dbHost =  "localhost"
    val dbPort =  "3306"
    val dbName = "vaigu"
    val dbUser = "root"
    val dbPassword = ""

    val jdbcUrl = "jdbc:mariadb://$dbHost:$dbPort/$dbName"

    Database.connect(
        url = jdbcUrl,
        driver = "org.mariadb.jdbc.Driver",
        user = dbUser,
        password = dbPassword
    )
}