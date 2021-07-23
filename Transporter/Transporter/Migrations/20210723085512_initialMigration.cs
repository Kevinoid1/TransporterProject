using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Transporter.Migrations
{
    public partial class initialMigration : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Shipments",
                columns: table => new
                {
                    TransactionId = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CustomerName = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    CustomerPhoneNo = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ReceiverName = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ReceiverPhoneNo = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SenderAddress = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ReceiverAddress = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    TransactionDate = table.Column<DateTime>(type: "datetime2", nullable: false),
                    TrackingNumber = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Shipments", x => x.TransactionId);
                });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Shipments");
        }
    }
}
