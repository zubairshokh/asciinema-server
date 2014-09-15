class StdoutDataUploader < CompressedFileUploader

  def store_dir
    store_dir_prefix +
      "#{model.class.to_s.underscore}/stdout/#{model.id}"
  end

end
