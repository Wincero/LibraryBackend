using LibraryBackend.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LibraryBackend.Controllers
{
    [ApiController]
    [Route("api/admin")]
    public class AdminController : ControllerBase
    {
        private readonly LibraryContext _context;

        public AdminController(LibraryContext context)
        {
            _context = context;
        }

        [HttpGet("requests")]
        public async Task<ActionResult<IEnumerable<PurchaseRequestDto>>> GetPurchaseRequests()
        {
            return await _context.PurchaseRequests
                .Select(pr => new PurchaseRequestDto
                {
                    Id = pr.Id,
                    BookId = pr.BookId,
                    Email = pr.Email,
                    Date = pr.Date
                })
                .ToListAsync();
        }
    }
}
