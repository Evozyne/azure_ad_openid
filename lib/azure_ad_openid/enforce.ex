defmodule AzureADOpenId.Enforce do
  @moduledoc """
  Helper functions for enforcing some conditions. The functions raise errors if the conditions
  aren't met.

  Useful for enforcing claims validation and destructuring :ok atoms without breaking the pipe.
  """

  def true?(final, []) do
    final
    |> Enum.reduce({true, []}, fn
      {:ok, _condition}, {check, errors} -> {check, errors}
      {:error, condition}, {check, errors} -> {check and false, [condition | errors]}
    end)
  end

  def true?(final, [{head, condition_name} | rest]) do
    case head do
      true -> List.insert_at(final, -1, {:ok, condition_name})
      false -> List.insert_at(final, -1, {:error, condition_name})
    end
    |> true?(rest)
  end

  def true!([], _), do: true

  def true!([{head, condition_name} | rest], error) do
    true!(head, error <> condition_name)
    true!(rest, error)
  end

  def true!(val, error) do
    if val do
      true
    else
      raise error
    end
  end

  def ok!({:ok, value}, _), do: value
  def ok!(_, error), do: raise(error)
end
