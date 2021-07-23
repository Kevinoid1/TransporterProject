using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Transporter.ViewModel
{
    public class CreateOrderVM
    {
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
