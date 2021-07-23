using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Transporter.Models
{
    public class TransporterDbContext:IdentityDbContext
    {
        public TransporterDbContext(DbContextOptions<TransporterDbContext> options): base(options)
        {

        }

        public DbSet<ShippingInfo> Shipments { get; set; }
    }
}
