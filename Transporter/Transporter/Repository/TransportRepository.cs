using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Transporter.Models;
using Transporter.ViewModel;

namespace Transporter.Repository
{
    public class TransportRepository : ITransportRepository
    {
        private readonly TransporterDbContext _context;

        public TransportRepository(TransporterDbContext context)
        {
            _context = context;
        }

        public async Task<bool> CheckIfTrackingNoExist(string trackingNumber)
        {
            return await _context.Shipments.AnyAsync(s => s.TrackingNumber.ToLower() == trackingNumber.ToLower());
        }

        public void DeleteOrder(int id)
        {
           var shipment = _context.Shipments.Find(id);
            _context.Shipments.Remove(shipment);
            
        }

        public async Task<IEnumerable<ShippingInfo>> GetAllShipmemnts()
        {
            return await _context.Shipments.ToListAsync();
        }

        public async Task<ShippingInfo> GetOrder(int id)
        {
            return await _context.Shipments.FirstOrDefaultAsync(s => s.TransactionId == id);
        }

        public async Task<ShippingInfo> GetOrder(string trackingNumber)
        {
            return await _context.Shipments.FirstOrDefaultAsync(s => s.TrackingNumber.ToLower() == trackingNumber.ToLower());
        }

        public void RegisterOrder(ShippingInfo model)
        {
            _context.Shipments.Add(model);
        }

        public async Task<bool> SaveAll()
        {
            return await _context.SaveChangesAsync() > 0;
        }

        public void UpdateOrder(ShippingInfo model)
        {
            _context.Shipments.Update(model);
        }
    }
}
