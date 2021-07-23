using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Transporter.Models
{
    public class ShippingInfo
    {
        [Key]
        public int TransactionId { get; set; }
        public string CustomerName { get; set; }
        public string CustomerPhoneNo { get; set; }
        public string ReceiverName { get; set; }
        public string ReceiverPhoneNo { get; set; }

        public string SenderAddress { get; set; }

        public string ReceiverAddress { get; set; }

        public DateTime TransactionDate { get; set; }
        public string TrackingNumber { get; set; }

        
    }
}
