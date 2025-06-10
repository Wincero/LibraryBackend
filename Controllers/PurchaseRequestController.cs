namespace LibraryBackend.Controllers
{
    using LibraryBackend.Data;
    using LibraryBackend.Models;
    using Microsoft.AspNetCore.Mvc;
    using System.ComponentModel.DataAnnotations;

    [ApiController]
    [Route("api/purchaserequests")]
    public class PurchaseRequestsController : ControllerBase
    {
        private readonly LibraryContext _context;
        private readonly ILogger<PurchaseRequestsController> _logger;

        public PurchaseRequestsController(
            LibraryContext context,
            ILogger<PurchaseRequestsController> logger)
        {
            _context = context;
            _logger = logger;
        }

        [HttpPost]
        public async Task<ActionResult<PurchaseRequestDto>> CreatePurchaseRequest([FromBody] CreatePurchaseRequestDto requestDto)
        {
            var request = new PurchaseRequest
            {
                BookId = requestDto.BookId,
                Email = requestDto.Email,
                Date = DateTime.UtcNow
            };

            _context.PurchaseRequests.Add(request);
            await _context.SaveChangesAsync();

            return Ok(new PurchaseRequestDto
            {
                Id = request.Id,
                BookId = request.BookId,
                Email = request.Email,
                Date = request.Date
            });
        }
    }

    public class CreatePurchaseRequestDto
    {
        [Required(ErrorMessage = "ID книги обязателен")]
        public int BookId { get; set; }

        [Required(ErrorMessage = "Email обязателен")]
        [EmailAddress(ErrorMessage = "Некорректный формат email")]
        public string Email { get; set; }
    }

    public class PurchaseRequestDto
    {
        public int Id { get; set; }
        public int BookId { get; set; }
        public string Email { get; set; }
        public DateTime Date { get; set; }
    }
}
